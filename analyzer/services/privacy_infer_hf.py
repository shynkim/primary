# -*- coding: utf-8 -*-
import os, json, re, threading
from typing import List, Dict, Any

import numpy as np
import torch
from torch import nn
from transformers import AutoTokenizer, AutoModel
from django.conf import settings

# ===== 기본 설정 =====
os.environ["TOKENIZERS_PARALLELISM"] = "false"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
DEFAULT_LABELS = ["LOC","CAM","MIC","MED","CNT","CALL","SMS","ACC","DEV_ID","DEV_ATTR","PUS"]

# settings.py에서 읽음
MODEL_DIR = getattr(settings, "POLICY_HF_MODEL_DIR", r"C:\Users\gram\primary-1\out_ps_ovr")
BASE_NAME = getattr(settings, "POLICY_HF_BASE", "distilbert-base-uncased")

# --- B안: thresholds.json 무시 + 퍼-라벨 임계치 프로파일 ---
TH_POL_DEFAULT = 0.999
TH_MULTI_SCALAR = 0.999  # 시작 스칼라 (아래 PER_LABEL_THRESHOLDS로 덮어씀)
PER_LABEL_THRESHOLDS = {
    "CALL":    0.9999,
    "SMS":     0.9999,
    "PUS":     0.9996,
    "ACC":     0.9994,
    "LOC":     0.9930,
    "DEV_ID":  0.9983,
    "DEV_ATTR":0.9950,
    "CNT":     0.9800,
    "CAM":     0.9970,
    "MIC":     0.9990,
    "MED":     0.9995,
}

_loader_lock = threading.Lock()
_tok = None
_model = None
_ALL_LABELS: List[str] = []

def _load_labels(path_dir: str) -> List[str]:
    p = os.path.join(path_dir, "labels.json")
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    return DEFAULT_LABELS

class OvRModel(nn.Module):
    """코랩 predict_privacy.py 와 동일 구조"""
    def __init__(self, base_model: str, num_labels: int):
        super().__init__()
        self.backbone = AutoModel.from_pretrained(base_model)
        h = self.backbone.config.hidden_size
        self.drop = nn.Dropout(0.1)
        self.classifiers = nn.ModuleList([nn.Linear(h, 1) for _ in range(num_labels)])
        self.cls_pol = nn.Linear(h, 1)

    def forward(self, input_ids, attention_mask):
        out = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
        h = self.drop(out.last_hidden_state[:, 0])
        multi_logits = torch.cat([clf(h) for clf in self.classifiers], dim=1)  # (B, L)
        pol_logits   = self.cls_pol(h)                                         # (B, 1)
        return multi_logits, pol_logits

def _extract_state_dict(obj):
    if isinstance(obj, dict):
        if "model" in obj and isinstance(obj["model"], dict):
            return obj["model"]
        any_key = next(iter(obj.keys()), None)
        if isinstance(any_key, str) and ("weight" in any_key or "." in any_key):
            return obj
    return obj

def _sentence_split(text: str) -> List[str]:
    chunks = re.split(r'(?<=[\.!?])\s+|\n+', str(text).strip())
    return [c for c in (t.strip() for t in chunks) if c]

def _ensure_loaded():
    """토크나이저/모델 1회 로드"""
    global _tok, _model, _ALL_LABELS
    if _model is not None and _tok is not None:
        return
    if not MODEL_DIR or not os.path.isdir(MODEL_DIR):
        raise FileNotFoundError(f"POLICY_HF_MODEL_DIR not found: {MODEL_DIR}")

    with _loader_lock:
        if _model is not None and _tok is not None:
            return

        labels = _load_labels(MODEL_DIR)
        _ALL_LABELS = list(labels)

        ckpt_path = os.path.join(MODEL_DIR, "best.ckpt")
        if not os.path.exists(ckpt_path):
            alt = os.path.join(MODEL_DIR, "state.pt")
            if os.path.exists(alt):
                ckpt_path = alt
            else:
                raise FileNotFoundError(f"checkpoint not found in {MODEL_DIR} (best.ckpt/state.pt)")

        model = OvRModel(BASE_NAME, num_labels=len(_ALL_LABELS)).to(DEVICE)
        # NOTE: 본인 파일이면 안전. 로드가 안 되면 weights_only=True 제거
        sd = torch.load(ckpt_path, map_location=DEVICE)
        sd = _extract_state_dict(sd)
        model.load_state_dict(sd, strict=False)
        model.eval()

        tok = AutoTokenizer.from_pretrained(BASE_NAME)

        _model = model
        _tok = tok

@torch.no_grad()
def predict_policy_text(
    text: str,
    *,
    split_long_doc: bool = True,       # 코랩과 동일
    aggregate: str = "max",            # "max" / "mean"
    thr_pol: float = TH_POL_DEFAULT,   # 0.999
    max_length: int = 256
) -> Dict[str, Any]:
    """
    코랩 B안과 동일 로직:
    - thresholds.json 무시
    - 고정 PER_LABEL_THRESHOLDS 적용
    """
    _ensure_loaded()

    # 1) 스칼라에서 시작 후 라벨 벡터화
    class_thresholds = np.full(len(_ALL_LABELS), float(TH_MULTI_SCALAR), dtype=np.float32)
    for i, lab in enumerate(_ALL_LABELS):
        if lab in PER_LABEL_THRESHOLDS:
            class_thresholds[i] = float(PER_LABEL_THRESHOLDS[lab])

    # 2) 토크나이즈/추론
    units = _sentence_split(text) if split_long_doc else [text]
    enc = _tok(units, truncation=True, padding=True, max_length=max_length, return_tensors="pt")
    enc = {k: v.to(DEVICE) for k, v in enc.items()}
    m_logits, p_logits = _model(**enc)
    m_probs = torch.sigmoid(m_logits).cpu().numpy()              # (n_sent, L)
    p_probs = torch.sigmoid(p_logits).cpu().numpy().reshape(-1)  # (n_sent,)

    # 3) 문서 단위 집계
    if len(units) == 1:
        agg_m = m_probs[0];          agg_p = float(p_probs[0])
    else:
        if aggregate == "mean":
            agg_m = m_probs.mean(axis=0);  agg_p = float(p_probs.mean())
        else:
            agg_m = m_probs.max(axis=0);   agg_p = float(p_probs.max())

    # 4) 임계치 적용
    pred_bin = (agg_m > class_thresholds).astype(int)
    pred_labels = [_ALL_LABELS[i] for i, v in enumerate(pred_bin) if v == 1]
    pred_polarity = "collect" if agg_p > float(thr_pol) else "not_collect"

    return {
        "pred_labels": pred_labels,
        "pred_polarity": pred_polarity,
        "probs_multi": {_ALL_LABELS[i]: float(agg_m[i]) for i in range(len(_ALL_LABELS))},
        "prob_polarity_collect": float(agg_p),
    }

def get_all_labels() -> List[str]:
    _ensure_loaded()
    return list(_ALL_LABELS)
