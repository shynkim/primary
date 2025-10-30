# -*- coding: utf-8 -*-
"""
개인정보 처리방침 텍스트 → 멀티라벨 예측 모듈
- predict_texts(text | list[str], ...) -> list[dict]
- out_ps_ovr 디렉토리 내:
    - best.ckpt 또는 state.pt (둘 중 하나 필수)
    - labels.json (라벨 이름 배열 or {id: name} 매핑) [권장]
    - thresholds.json (라벨별 임계치)                [선택]
"""

from __future__ import annotations
import os, json, re
from typing import List, Union, Dict, Any

import numpy as np
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel

# ─────────────────────────────────────────────────────────────────────────────
# 경로 설정: 프로젝트 루트/manage.py 기준의 out_ps_ovr
# settings.OUT_PS_OVR_DIR 가 있으면 그걸 우선 사용
try:
    from django.conf import settings  # django context 내
    PROJECT_ROOT = str(settings.BASE_DIR)
    CKPT_DIR = str(getattr(settings, "OUT_PS_OVR_DIR", os.path.join(PROJECT_ROOT, "out_ps_ovr")))
except Exception:
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    CKPT_DIR = os.path.join(PROJECT_ROOT, "out_ps_ovr")

LABELS_PATH = os.path.join(CKPT_DIR, "labels.json")
THRESH_PATH  = os.path.join(CKPT_DIR, "thresholds.json")

# ─────────────────────────────────────────────────────────────────────────────
# 라벨 로딩
def _load_labels() -> List[str]:
    """
    labels.json이 있으면 거기서 로드.
    - 배열 형태 ["카메라","위치",...] 혹은
    - 매핑 형태 {"0":"카메라","1":"위치",...} 둘 다 지원
    없으면 기본 코드 라벨로 폴백.
    """
    default_labels = ["LOC","CAM","MIC","MED","CNT","CALL","SMS","ACC","DEV_ID","DEV_ATTR","PUS"]
    if not os.path.exists(LABELS_PATH):
        return default_labels

    with open(LABELS_PATH, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if isinstance(obj, list):
        return [str(x) for x in obj]
    if isinstance(obj, dict):
        # 키가 정수/문자 정수라고 가정하고 id 순으로 정렬
        try:
            items = sorted(((int(k), v) for k, v in obj.items()), key=lambda x: x[0])
            return [str(v) for _, v in items]
        except Exception:
            # dict지만 id 정렬이 불가하면 값만 나열
            return [str(v) for v in obj.values()]
    return default_labels

ALL_LABELS: List[str] = _load_labels()
NUM_LABELS = len(ALL_LABELS)

# ─────────────────────────────────────────────────────────────────────────────
# 임계치 로딩
def _load_thresholds(default_thr: float = 0.5) -> np.ndarray:
    if not os.path.exists(THRESH_PATH):
        return np.full((NUM_LABELS,), float(default_thr), dtype=np.float32)
    with open(THRESH_PATH, "r", encoding="utf-8") as f:
        obj = json.load(f)
    vec = []
    for lab in ALL_LABELS:
        vec.append(float(obj.get(lab, default_thr)))
    return np.array(vec, dtype=np.float32)

# ─────────────────────────────────────────────────────────────────────────────
# 모델 정의 (OvR 헤드)
class OvRModel(nn.Module):
    def __init__(self, base_name: str, num_labels: int):
        super().__init__()
        self.backbone = AutoModel.from_pretrained(base_name)
        h = self.backbone.config.hidden_size
        self.drop = nn.Dropout(0.1)
        self.classifiers = nn.ModuleList([nn.Linear(h, 1) for _ in range(num_labels)])
        self.cls_pol = nn.Linear(h, 1)  # 수집/비수집 이진

    def forward(self, input_ids, attention_mask):
        out = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
        h = self.drop(out.last_hidden_state[:, 0])
        multi_logits = torch.cat([clf(h) for clf in self.classifiers], dim=1)  # [B, L]
        pol_logits   = self.cls_pol(h)                                         # [B, 1]
        return multi_logits, pol_logits

# ─────────────────────────────────────────────────────────────────────────────
# 전역 싱글톤 (캐시)
_DEVICE   = "cuda" if torch.cuda.is_available() else "cpu"
_BASE     = "distilbert-base-uncased"   # 팀 모델이 사용한 프리트레인 이름
_MODEL: OvRModel | None = None
_TOKEN: AutoTokenizer | None = None
_THRESH_VEC: np.ndarray | None = None

def _pick_ckpt_path() -> str:
    for fname in ("best.ckpt", "state.pt"):
        p = os.path.join(CKPT_DIR, fname)
        if os.path.exists(p):
            return p
    raise FileNotFoundError(f"모델 체크포인트가 없습니다. ({CKPT_DIR}/best.ckpt 또는 state.pt)")

def _load_once():
    global _MODEL, _TOKEN, _THRESH_VEC
    if _MODEL is not None and _TOKEN is not None and _THRESH_VEC is not None:
        return

    ckpt_path = _pick_ckpt_path()

    # 토크나이저/모델 초기화
    _TOKEN = AutoTokenizer.from_pretrained(_BASE)
    m = OvRModel(_BASE, NUM_LABELS).to(_DEVICE)

    # state_dict 로드 (best.ckpt 또는 state.pt)
    ckpt = torch.load(ckpt_path, map_location=_DEVICE)
    state_dict = ckpt.get("model", ckpt) if isinstance(ckpt, dict) else ckpt
    m.load_state_dict(state_dict, strict=False)
    m.eval()
    _MODEL = m

    # 임계치 벡터
    _THRESH_VEC = _load_thresholds(default_thr=0.5)

# ─────────────────────────────────────────────────────────────────────────────
# 유틸
_SENT_SPLIT_RE = re.compile(r'(?<=[\.!?])\s+|\n+')

def _split_sentences(text: str) -> List[str]:
    chunks = _SENT_SPLIT_RE.split(str(text).strip())
    return [c.strip() for c in chunks if c and c.strip()]

# ─────────────────────────────────────────────────────────────────────────────
# 공개 API
@torch.no_grad()
def predict_texts(
    texts: Union[str, List[str]],
    th_multi: float = 0.5,
    th_pol: float = 0.5,
    max_length: int = 256,
    split_long_doc: bool = False,
    aggregate: str = "max",   # "max" or "mean"
) -> List[Dict[str, Any]]:
    """
    Args:
        texts: 단일 문자열 또는 문자열 리스트
        th_multi: 임계치(기본값). thresholds.json이 있으면 라벨별 값으로 대체
        th_pol: 수집/비수집 이진 임계치
        max_length: 토크나이저 최대 길이
        split_long_doc: True면 문장 단위 슬라이스 후 집계
        aggregate: "max" 또는 "mean"
    Returns:
        [
          {
            "input_text": str,
            "pred_labels": [라벨, ...],              # 라벨 이름은 labels.json 기준
            "pred_polarity": "collect"|"not_collect",
            "probs_multi": {라벨: 확률, ...},
            "prob_polarity_collect": float
          }, ...
        ]
    """
    _load_once()  # 모델/토크나/임계치 캐시 로드
    assert _MODEL is not None and _TOKEN is not None and _THRESH_VEC is not None

    # thresholds.json 없으면 th_multi로 채움
    thr_vec = _THRESH_VEC if _THRESH_VEC is not None else np.full((NUM_LABELS,), float(th_multi), dtype=np.float32)

    if isinstance(texts, str):
        texts = [texts]

    results: List[Dict[str, Any]] = []

    for doc in texts:
        units = _split_sentences(doc) if split_long_doc else [doc]

        enc = _TOKEN(
            units,
            truncation=True,
            padding=True,
            max_length=max_length,
            return_tensors="pt",
        )
        enc = {k: v.to(_DEVICE) for k, v in enc.items()}

        m_logits, p_logits = _MODEL(**enc)
        m_probs = torch.sigmoid(m_logits).cpu().numpy()           # [U, L]
        p_probs = torch.sigmoid(p_logits).cpu().numpy().reshape(-1)  # [U]

        if len(units) == 1:
            agg_m = m_probs[0]
            agg_p = float(p_probs[0])
        else:
            if aggregate == "mean":
                agg_m = m_probs.mean(axis=0)
                agg_p = float(p_probs.mean())
            else:  # "max" 기본
                agg_m = m_probs.max(axis=0)
                agg_p = float(p_probs.max())

        # 멀티라벨 임계치 적용
        pred_bin = (agg_m > thr_vec).astype(np.int32)
        picked = [ALL_LABELS[i] for i, v in enumerate(pred_bin) if v == 1]

        result = {
            "input_text": doc,
            "pred_labels": picked,
            "pred_polarity": "collect" if agg_p > float(th_pol) else "not_collect",
            "probs_multi": {ALL_LABELS[i]: float(agg_m[i]) for i in range(NUM_LABELS)},
            "prob_polarity_collect": float(agg_p),
        }
        results.append(result)

    return results
