# -*- coding: utf-8 -*-
"""
개인정보 처리방침 정책 텍스트 멀티라벨 예측 추론용 모듈
- predict_texts: 입력 텍스트(단문 또는 문서)를 받아 라벨 예측 결과 리턴
"""
import os, json
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModel

# 프로젝트 루트: manage.py가 있는 디렉토리에서 out_ps_ovr 기준
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CKPT_DIR = os.path.join(PROJECT_ROOT, "out_ps_ovr")

import torch.nn as nn
class OvRModel(nn.Module):
    def __init__(self, base):
        super().__init__()
        self.backbone = AutoModel.from_pretrained(base)
        h = self.backbone.config.hidden_size
        self.drop = nn.Dropout(0.1)
        self.classifiers = nn.ModuleList([nn.Linear(h, 1) for _ in range(len(ALL_LABELS))])
        self.cls_pol = nn.Linear(h, 1)
    def forward(self, input_ids, attention_mask):
        out = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
        h = self.drop(out.last_hidden_state[:, 0])
        multi_logits = torch.cat([clf(h) for clf in self.classifiers], dim=1)
        pol_logits = self.cls_pol(h)
        return multi_logits, pol_logits

def predict_texts(
    texts,
    ckpt_dir=DEFAULT_CKPT_DIR,
    th_multi=0.5,
    th_pol=0.5,
    max_length=256,
    split_long_doc=False,
    aggregate="max"
):
    # 라벨 목록
    ALL_LABELS = ["LOC","CAM","MIC","MED","CNT","CALL","SMS","ACC","DEV_ID","DEV_ATTR","PUS"]
    DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
    BASE = "distilbert-base-uncased"
    # 체크포인트 로드: best.ckpt > state.pt 우선순위
    for fname in ["best.ckpt", "state.pt"]:
        cpath = os.path.join(ckpt_dir, fname)
        if os.path.exists(cpath):
            ckpt_path = cpath
            break
    else:
        raise FileNotFoundError("best.ckpt 또는 state.pt가 없습니다. (out_ps_ovr 폴더 확인)")

    # 모델 정의
    import torch.nn as nn
    class OvRModel(nn.Module):
        def __init__(self, base):
            super().__init__()
            self.backbone = AutoModel.from_pretrained(base)
            h = self.backbone.config.hidden_size
            self.drop = nn.Dropout(0.1)
            self.classifiers = nn.ModuleList([nn.Linear(h, 1) for _ in range(len(ALL_LABELS))])
            self.cls_pol = nn.Linear(h, 1)
        def forward(self, input_ids, attention_mask):
            out = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
            h = self.drop(out.last_hidden_state[:, 0])
            multi_logits = torch.cat([clf(h) for clf in self.classifiers], dim=1)
            pol_logits = self.cls_pol(h)
            return multi_logits, pol_logits
    # 로드
    model = OvRModel(BASE).to(DEVICE)
    ckpt = torch.load(ckpt_path, map_location=DEVICE)
    state_dict = ckpt['model'] if isinstance(ckpt, dict) and 'model' in ckpt else ckpt
    model.load_state_dict(state_dict)
    model.eval()
    tok = AutoTokenizer.from_pretrained(BASE)
    if isinstance(texts, str):
        texts = [texts]
    @torch.no_grad()
    def simple_sentence_split(text):
        import re
        chunks = re.split(r'(?<=[\.!?])\s+|\n+', str(text).strip())
        return [c for c in (t.strip() for t in chunks) if c]
    # 임계치 벡터 로딩
    class_thresholds = th_multi  # <<=== 기본값 반드시 선행
    thr_path = os.path.join(ckpt_dir, "thresholds.json")
    if os.path.exists(thr_path):
        obj = json.load(open(thr_path, "r"))
        class_thresholds = np.array([float(obj.get(lab, th_multi)) for lab in ALL_LABELS], dtype=np.float32)
    use_vec = isinstance(class_thresholds, (list, tuple, np.ndarray))
    results = []
    for doc in texts:
        units = simple_sentence_split(doc) if split_long_doc else [doc]
        with torch.no_grad():
            enc = tok(units, truncation=True, padding=True, max_length=max_length, return_tensors="pt")
            enc = {k: v.to(DEVICE) for k, v in enc.items()}
            m_logits, p_logits = model(**enc)
            m_probs = torch.sigmoid(m_logits).cpu().numpy()
            p_probs = torch.sigmoid(p_logits).cpu().numpy().reshape(-1)
        if len(units) == 1:
            agg_m = m_probs[0]
            agg_p = float(p_probs[0])
        else:
            if aggregate == "mean":
                agg_m = m_probs.mean(axis=0); agg_p = float(p_probs.mean())
            else:
                agg_m = m_probs.max(axis=0);   agg_p = float(p_probs.max())
        if use_vec:
            thr = np.asarray(class_thresholds, dtype=np.float32)
            pred_bin = (agg_m > thr).astype(int)
        else:
            pred_bin = (agg_m > float(class_thresholds)).astype(int)
        pred_labels = [ALL_LABELS[i] for i, v in enumerate(pred_bin) if v == 1]
        pred_polarity = "collect" if agg_p > float(th_pol) else "not_collect"
        results.append({
            "input_text": doc,
            "pred_labels": pred_labels,
            "pred_polarity": pred_polarity,
            "probs_multi": {ALL_LABELS[i]: float(agg_m[i]) for i in range(len(ALL_LABELS))},
            "prob_polarity_collect": float(agg_p)
        })
    return results
