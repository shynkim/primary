import os
import re
import json
from typing import Dict, List, Optional

# Try optional dependencies (scikit-learn joblib path remains supported)
try:
    import joblib
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

# Torch / Transformers optional (BERT inference)
try:
    import torch
    from torch import nn
    from transformers import AutoTokenizer, AutoModel
    TORCH_AVAILABLE = True
except Exception:
    TORCH_AVAILABLE = False

DEFAULT_SKLEARN_MODEL = os.path.join(os.path.dirname(__file__), 'models', 'policy_classifier.joblib')
DEFAULT_BERT_CKPT = os.path.join(os.path.dirname(__file__), 'models', 'best.ckpt')


class PolicyMLAnalyzer:
    """Policy analyzer with multiple inference fallbacks.

    - If a BERT checkpoint + torch/transformers are available, uses the OvR BERT model for multi-label
      inference (lazy-loaded when first needed).
    - Else if a sklearn joblib bundle exists (vectorizer+model), uses that.
    - Always augments with keyword heuristics to ensure the three core flags are set.

    The public API is `analyze_text(text: str) -> Dict` which returns a dict containing
    keys: status, contains_location, contains_camera, contains_contact, mentioned_permissions, summary, key_sentences
    """

    def __init__(self, sklearn_model_path: Optional[str] = None, bert_ckpt_path: Optional[str] = None, bert_base: str = None):
        self.sklearn_model_path = sklearn_model_path or DEFAULT_SKLEARN_MODEL
        self.bert_ckpt_path = bert_ckpt_path or DEFAULT_BERT_CKPT
        self.bert_base = bert_base or 'distilbert-base-uncased'

        # sklearn objects (optional)
        self.sklearn_model = None
        self.sklearn_vectorizer = None
        if SKLEARN_AVAILABLE and os.path.exists(self.sklearn_model_path):
            try:
                bundle = joblib.load(self.sklearn_model_path)
                self.sklearn_vectorizer = bundle.get('vectorizer')
                self.sklearn_model = bundle.get('model')
            except Exception:
                self.sklearn_model = None
                self.sklearn_vectorizer = None

        # BERT lazy objects
        self.bert_model = None
        self.bert_tok = None
        self.bert_thresholds = None
        self._bert_loaded = False

    # --------------------------
    # Lightweight helpers
    # --------------------------
    def _simple_keyword_checks(self, text: str) -> Dict:
        lower = (text or '').lower()
        return {
            'contains_location': any(k in lower for k in ['위치', 'location', 'gps', 'latitude', 'longitude', '위치정보']),
            'contains_camera': any(k in lower for k in ['카메라', 'camera', '촬영', '사진']),
            'contains_contact': any(k in lower for k in ['연락처', 'contacts', '주소록', 'phonebook']),
        }

    def _extract_key_sentences(self, text: str, max_sents: int = 5) -> List[str]:
        sentences = re.split(r'[\.\n\r]+', text)
        key_sents = []
        for s in sentences:
            sl = s.strip()
            if not sl:
                continue
            low = sl.lower()
            if any(k in low for k in ['위치', 'location', 'gps']) and 'location' not in key_sents:
                key_sents.append(sl)
            if any(k in low for k in ['카메라', 'camera']) and 'camera' not in key_sents:
                key_sents.append(sl)
            if any(k in low for k in ['연락처', 'contacts']) and 'contact' not in key_sents:
                key_sents.append(sl)
            if len(key_sents) >= max_sents:
                break
        return key_sents

    # --------------------------
    # BERT helpers (lazy load)
    # --------------------------
    class OvRModel(nn.Module):
        def __init__(self, base, n_labels=11):
            super().__init__()
            self.backbone = AutoModel.from_pretrained(base)
            h = self.backbone.config.hidden_size
            self.drop = nn.Dropout(0.1)
            self.classifiers = nn.ModuleList([nn.Linear(h, 1) for _ in range(n_labels)])
            self.cls_pol = nn.Linear(h, 1)

        def forward(self, input_ids, attention_mask, token_type_ids=None):
            out = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
            h = self.drop(out.last_hidden_state[:, 0])
            multi_logits = torch.cat([clf(h) for clf in self.classifiers], dim=1)
            pol_logits = self.cls_pol(h)
            return multi_logits, pol_logits

    def _extract_state_dict(self, obj):
        if isinstance(obj, dict):
            if 'model' in obj and isinstance(obj['model'], dict):
                return obj['model']
            any_key = next(iter(obj.keys()), None)
            if isinstance(any_key, str) and ('weight' in any_key or '.' in any_key):
                return obj
        return obj

    def _load_bert(self):
        if self._bert_loaded:
            return
        self._bert_loaded = True
        if not TORCH_AVAILABLE:
            return
        if not os.path.exists(self.bert_ckpt_path):
            return
        try:
            # create model skeleton and load state dict
            model = self.OvRModel(self.bert_base)
            ckpt = torch.load(self.bert_ckpt_path, map_location='cpu')
            state = self._extract_state_dict(ckpt)
            model.load_state_dict(state)
            model.eval()
            self.bert_model = model.to('cpu')
            self.bert_tok = AutoTokenizer.from_pretrained(self.bert_base)
            # try load thresholds if present next to checkpoint
            thr_path = os.path.join(os.path.dirname(self.bert_ckpt_path), 'thresholds.json')
            if os.path.exists(thr_path):
                obj = json.load(open(thr_path, 'r', encoding='utf-8'))
                # keep numpy-free simple list
                self.bert_thresholds = [float(obj.get(k, 0.5)) for k in obj.keys()]
        except Exception:
            # any failure leaves bert_model as None
            self.bert_model = None
            self.bert_tok = None

    def _predict_with_bert(self, text: str, max_length: int = 256, aggregate: str = 'max'):
        # returns dict with keys: pred_labels (list), probs (dict label->prob), polarity_prob
        if not TORCH_AVAILABLE:
            raise RuntimeError('torch/transformers not available')
        self._load_bert()
        if not self.bert_model or not self.bert_tok:
            raise RuntimeError('BERT model/tokenizer not loaded')

        units = [text]
        enc = self.bert_tok(units, truncation=True, padding=True, max_length=max_length, return_tensors='pt')
        enc = {k: v for k, v in enc.items()}
        with torch.no_grad():
            logits_m, logits_p = self.bert_model(enc['input_ids'], enc['attention_mask'])
            probs_m = torch.sigmoid(logits_m).cpu().numpy()[0]
            probs_p = float(torch.sigmoid(logits_p).cpu().numpy().reshape(-1)[0])

        # thresholds
        if self.bert_thresholds and len(self.bert_thresholds) == len(probs_m):
            thr = self.bert_thresholds
        else:
            thr = [0.5] * len(probs_m)

        pred_bin = [(probs_m[i] > thr[i]) for i in range(len(probs_m))]
        # Map top-11 labels to names if labels.json exists near the checkpoint
        labels_path = os.path.join(os.path.dirname(self.bert_ckpt_path), 'labels.json')
        if os.path.exists(labels_path):
            try:
                lbls = json.load(open(labels_path, 'r', encoding='utf-8'))
            except Exception:
                lbls = []
        else:
            lbls = []

        if not lbls or len(lbls) != len(probs_m):
            # fallback labels (partial mapping)
            lbls = ['LOC','CAM','MIC','MED','CNT','CALL','SMS','ACC','DEV_ID','DEV_ATTR','PUS'][:len(probs_m)]

        pred_labels = [lbls[i] for i,v in enumerate(pred_bin) if v]
        probs_dict = {lbls[i]: float(probs_m[i]) for i in range(len(probs_m))}
        return {
            'pred_labels': pred_labels,
            'probs_multi': probs_dict,
            'prob_polarity_collect': probs_p
        }

    # --------------------------
    # Public API
    # --------------------------
    def analyze_text(self, text: str) -> Dict:
        text = (text or '').strip()
        result = {
            'status': 'completed',
            'contains_location': False,
            'contains_camera': False,
            'contains_contact': False,
            'mentioned_permissions': [],
            'summary': text[:300] + '...' if len(text) > 300 else text,
            'key_sentences': []
        }

        if not text:
            result['status'] = 'failed'
            result['error'] = 'empty_text'
            return result

        # 1) Try BERT inference if available
        bert_ok = TORCH_AVAILABLE and os.path.exists(self.bert_ckpt_path)
        bert_output = None
        if bert_ok:
            try:
                out = self._predict_with_bert(text)
                bert_output = out
                # map BERT label predictions to the three flags
                # commonly: LOC -> location, CAM -> camera, CNT -> contact
                lbls = out.get('pred_labels', [])
                if any(l.upper().startswith('LOC') for l in lbls):
                    result['contains_location'] = True
                if any(l.upper().startswith('CAM') for l in lbls):
                    result['contains_camera'] = True
                if any(l.upper().startswith('CNT') or l.upper().startswith('CNT') for l in lbls):
                    result['contains_contact'] = True
            except Exception:
                bert_output = None

        # 2) Try sklearn model if available (legacy)
        if self.sklearn_model and self.sklearn_vectorizer:
            try:
                X = self.sklearn_vectorizer.transform([text])
                preds = self.sklearn_model.predict(X)
                # defensive: preds may be binary vector-like or array
                if hasattr(preds, 'tolist'):
                    flat = preds[0].tolist()
                    if len(flat) >= 3:
                        result['contains_location'] = result['contains_location'] or bool(flat[0])
                        result['contains_camera'] = result['contains_camera'] or bool(flat[1])
                        result['contains_contact'] = result['contains_contact'] or bool(flat[2])
            except Exception:
                pass

        # 3) Keyword heuristics (always run to augment)
        kws = self._simple_keyword_checks(text)
        result['contains_location'] = result['contains_location'] or kws['contains_location']
        result['contains_camera'] = result['contains_camera'] or kws['contains_camera']
        result['contains_contact'] = result['contains_contact'] or kws['contains_contact']

        # map APK permissions to mentions (simple heuristics)
        mapping = {
            'android.permission.ACCESS_FINE_LOCATION': 'contains_location',
            'android.permission.ACCESS_COARSE_LOCATION': 'contains_location',
            'android.permission.CAMERA': 'contains_camera',
            'android.permission.READ_CONTACTS': 'contains_contact',
            'android.permission.WRITE_CONTACTS': 'contains_contact',
        }
        mentioned = [perm for perm, key in mapping.items() if result.get(key)]
        result['mentioned_permissions'] = mentioned

        # key sentences
        result['key_sentences'] = self._extract_key_sentences(text)
        return result

