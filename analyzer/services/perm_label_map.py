# analyzer/services/perm_label_map.py
# -*- coding: utf-8 -*-
import csv, os, glob, threading
from typing import Dict, List, Set, Tuple, Optional, Iterable

import pandas as pd
from django.conf import settings

# ── 설정 ─────────────────────────────────────────────────────────
_SOURCES = list(getattr(settings, "PERMISSION_LABEL_SOURCES", []))
_lock = threading.Lock()
_perm2labels: Optional[Dict[str, Set[str]]] = None
_loaded_from: List[str] = []

# 헤더 후보 (대소문자 무시)  ← 여기서 Tag/Permission을 우선 인식
PERM_COL_CANDS  = {"permission", "perm", "android_permission", "name"}
LABEL_COL_CANDS = {"tag", "tags", "label", "labels", "mapped_label"}

def _norm_perm(p: str) -> str:
    return str(p).strip()

def _norm_label(l: str) -> str:
    return str(l).strip().upper()

def _split_labels(cell: str) -> List[str]:
    if cell is None:
        return []
    s = str(cell).strip()
    if not s:
        return []
    s = s.replace(";", ",")
    items = [x.strip() for x in s.split(",")]
    return [_norm_label(x) for x in items if x]

def _iter_files() -> Iterable[str]:
    """설정에서 폴더/파일 받아 *.csv, *.xlsx, *.xls만 산출"""
    seen = set()
    if not _SOURCES:
        # 기본값: BASE_DIR/mapping 폴더
        base = str(getattr(settings, "BASE_DIR", os.getcwd()))
        default_dir = os.path.join(base, "mapping")
        if os.path.isdir(default_dir):
            _SOURCES.append(default_dir)

    for src in _SOURCES:
        if not src:
            continue
        p = os.path.normpath(src)
        if os.path.isdir(p):
            for pat in ("*.csv", "*.xlsx", "*.xls"):
                for f in glob.glob(os.path.join(p, pat)):
                    nf = os.path.normpath(f)
                    if nf not in seen:
                        seen.add(nf); yield nf
        elif os.path.isfile(p):
            ext = os.path.splitext(p)[1].lower()
            if ext in (".csv", ".xlsx", ".xls"):
                nf = os.path.normpath(p)
                if nf not in seen:
                    seen.add(nf); yield nf

def _find_cols(cols: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """헤더에서 Permission/Tag 컬럼명을 찾아 원본 이름으로 반환"""
    perm_col = None
    label_col = None
    for c in cols:
        lc = c.lower().strip()
        if lc in PERM_COL_CANDS and perm_col is None:
            perm_col = c
        if lc in LABEL_COL_CANDS and label_col is None:
            label_col = c
    return perm_col, label_col

def _load_csv(path: str, mapping: Dict[str, Set[str]]):
    with open(path, "r", encoding="utf-8") as f:
        rd = csv.DictReader(f)
        if not rd.fieldnames:
            return
        perm_col, label_col = _find_cols(list(rd.fieldnames))
        if not perm_col or not label_col:
            raise ValueError(f"{path}: columns must include Permission/Tag (or compatibles)")
        for row in rd:
            perm = _norm_perm(row.get(perm_col, ""))
            labs = _split_labels(row.get(label_col, ""))
            if perm and labs:
                mapping.setdefault(perm, set()).update(labs)

def _load_excel(path: str, mapping: Dict[str, Set[str]]):
    xls = pd.ExcelFile(path)
    for sheet in xls.sheet_names:
        df = pd.read_excel(path, sheet_name=sheet)
        if df.empty:
            continue
        cols = list(map(str, df.columns))
        perm_col, label_col = _find_cols(cols)
        if not perm_col or not label_col:
            # 명시적 컬럼이 없으면 스킵
            continue
        for _, row in df.iterrows():
            perm = _norm_perm(row.get(perm_col, ""))
            labs = _split_labels(row.get(label_col, ""))
            if perm and labs:
                mapping.setdefault(perm, set()).update(labs)

def _load_all():
    """모든 파일을 읽어 하나의 perm→labels 매핑으로 병합"""
    global _perm2labels, _loaded_from
    if _perm2labels is not None:
        return
    with _lock:
        if _perm2labels is not None:
            return
        mapping: Dict[str, Set[str]] = {}
        loaded: List[str] = []
        any_ok = False

        for path in _iter_files():
            ext = os.path.splitext(path)[1].lower()
            try:
                if ext == ".csv":
                    _load_csv(path, mapping); loaded.append(path); any_ok = True
                elif ext in (".xlsx", ".xls"):
                    _load_excel(path, mapping); loaded.append(path); any_ok = True
            except Exception as e:
                print(f"[perm_label_map] skip {path}: {e}")

        if not any_ok:
            raise FileNotFoundError(f"No valid mapping files. Check PERMISSION_LABEL_SOURCES={_SOURCES}")

        _perm2labels = mapping
        _loaded_from = loaded

def map_permissions_to_labels(perms: List[str]) -> Tuple[Set[str], Dict[str, Set[str]], Set[str]]:
    """
    입력 퍼미션 목록 -> (라벨집합, 퍼미션별라벨, 미지정퍼미션)
    """
    _load_all(); assert _perm2labels is not None
    labels_from_perms: Set[str] = set()
    label_by_perm: Dict[str, Set[str]] = {}
    unknown: Set[str] = set()

    for p in perms or []:
        key = _norm_perm(p)
        labs = _perm2labels.get(key)
        if labs:
            labels_from_perms.update(labs)
            label_by_perm[key] = set(labs)
        else:
            unknown.add(key)
    return labels_from_perms, label_by_perm, unknown

def sources_loaded() -> List[str]:
    _load_all(); return list(_loaded_from)

def reload_mapping():
    global _perm2labels, _loaded_from
    with _lock:
        _perm2labels = None; _loaded_from = []
    _load_all()
