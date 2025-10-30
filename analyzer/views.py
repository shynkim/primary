# -*- coding: utf-8 -*-
from __future__ import annotations
import os, mimetypes
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib import messages
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.utils import timezone
from django.views.decorators.http import require_POST

from .models import APKAnalysis
from .apk_analyzer import APKAnalyzer
from analyzer.policy_predict import predict_texts

# ─────────────────────────────────────────────────────
# 권한 → 라벨 매핑 (EekeeK 정책 모델과 동일)
PERM_TO_LABEL = {
    "android.permission.ACCESS_FINE_LOCATION": "LOC",
    "android.permission.ACCESS_COARSE_LOCATION": "LOC",
    "android.permission.CAMERA": "CAM",
    "android.permission.RECORD_AUDIO": "MIC",
    "android.permission.READ_CONTACTS": "CNT",
    "android.permission.WRITE_CONTACTS": "CNT",
    "android.permission.READ_CALL_LOG": "CALL",
    "android.permission.WRITE_CALL_LOG": "CALL",
    "android.permission.READ_SMS": "SMS",
    "android.permission.SEND_SMS": "SMS",
    "android.permission.ACTIVITY_RECOGNITION": "ACC",
    "android.permission.READ_PHONE_STATE": "DEV_ATTR",
    "android.permission.POST_NOTIFICATIONS": "PUS",
}

def _labels_from_permissions(perms):
    return {PERM_TO_LABEL[p] for p in perms if p in PERM_TO_LABEL}

def _build_comparison(perm_labels, policy_labels):
    pol = set(policy_labels or [])
    matched = sorted(perm_labels & pol)
    only_perm = sorted(perm_labels - pol)
    only_policy = sorted(pol - perm_labels)
    total = len(perm_labels | pol)
    pct = round(100 * len(matched) / total, 1) if total else 0.0
    return {
        "matched": matched,
        "only_perm": only_perm,
        "only_policy": only_policy,
        "totals": {"matched": len(matched), "total": total, "percentage": pct},
    }

def _is_apk_file(up):
    name = (up.name or "").lower()
    ctype = (getattr(up, "content_type", "") or mimetypes.guess_type(name)[0] or "").lower()
    return name.endswith(".apk") and ("application/vnd.android.package-archive" in ctype or ctype == "")

# ─────────────────────────────────────────────────────
def index(request):
    return render(request, "analyzer/index.html")

def analysis_list(request):
    return render(request, "analyzer/analysis_list.html", {"analyses": APKAnalysis.objects.all()})

def analysis_detail(request, analysis_id):
    obj = get_object_or_404(APKAnalysis, id=analysis_id)
    return render(request, "analyzer/analysis_detail.html", {"analysis": obj})

def analysis_status(request, analysis_id):
    obj = get_object_or_404(APKAnalysis, id=analysis_id)
    return JsonResponse({"status": obj.status, "error_message": obj.error_message})

# ─────────────────────────────────────────────────────
def upload_apk(request):
    if request.method != "POST":
        return redirect("analyzer:index")

    apk_file = request.FILES.get("apk_file")
    policy_text = (request.POST.get("policy_text") or "").strip()

    if not apk_file or not _is_apk_file(apk_file):
        messages.error(request, "APK 파일(.apk)만 업로드 가능합니다.")
        return redirect("analyzer:index")
    if apk_file.size > 50 * 1024 * 1024:
        messages.error(request, "파일 크기는 50MB를 초과할 수 없습니다.")
        return redirect("analyzer:index")

    obj = APKAnalysis.objects.create(file_name=apk_file.name, file_size=apk_file.size, status="pending")
    temp_path = default_storage.save(f"temp/{apk_file.name}", ContentFile(apk_file.read()))
    full_path = default_storage.path(temp_path)

    try:
        obj.status = "analyzing"
        obj.analysis_time = timezone.now()
        obj.save(update_fields=["status", "analysis_time"])

        # ── 분석 수행 ────────────────────────────────
        analyzer = APKAnalyzer(full_path)
        csv_output_dir = os.path.join(default_storage.location, "analysis_csv", str(obj.id))
        os.makedirs(csv_output_dir, exist_ok=True)
        result = analyzer.analyze_with_csv_export(csv_output_dir)

        if result.get("status") == "completed":
            basic = result.get("basic_info") or {}
            obj.package_name = basic.get("package_name") or ""
            obj.version_name = basic.get("version_name") or ""
            obj.version_code = basic.get("version_code") or ""
            obj.min_sdk = basic.get("min_sdk") or ""
            obj.target_sdk = basic.get("target_sdk") or ""
            obj.permissions = result.get("permissions") or []
            obj.activities = result.get("activities") or []
            obj.services = result.get("services") or []
            obj.receivers = result.get("receivers") or []
            obj.api_calls = result.get("api_calls") or []
            obj.security_analysis = result.get("security_analysis") or {}

            # 정책 예측 (있을 경우)
            policy_labels = []
            if policy_text:
                try:
                    res = predict_texts(policy_text)
                    if isinstance(res, list) and res:
                        policy_labels = res[0].get("pred_labels", [])
                except Exception:
                    policy_labels = ["predict_fail"]
            obj.policy_labels = policy_labels

            perm_labels = _labels_from_permissions(obj.permissions or [])
            obj.comparison = _build_comparison(perm_labels, policy_labels)
            obj.status = "completed"

        else:
            obj.status = "failed"
            obj.error_message = result.get("error") or "분석 실패"

        obj.save()
        return redirect("analyzer:analysis_detail", analysis_id=obj.id)

    except Exception as e:
        obj.status = "failed"
        obj.error_message = str(e)
        obj.analysis_time = timezone.now()
        obj.save(update_fields=["status", "error_message", "analysis_time"])
        messages.error(request, f"분석 중 오류 발생: {e}")
        return redirect("analyzer:index")

    finally:
        try:
            default_storage.delete(temp_path)
        except Exception:
            pass

# ─────────────────────────────────────────────────────
@require_POST
def policy_predict_api(request):
    import json
    try:
        body = json.loads(request.body.decode("utf-8"))
        texts = body.get("texts") or []
        if not isinstance(texts, list) or not texts:
            return JsonResponse({"error": "texts 배열이 필요합니다."}, status=400)
        results = predict_texts(texts)
        return JsonResponse(results, safe=False, json_dumps_params={"ensure_ascii": False})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
