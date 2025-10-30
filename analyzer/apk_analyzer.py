# -*- coding: utf-8 -*-
"""
APK 파일 분석기 (Androguard 전용)
- aapt 없이 동작
- APK 파일만 허용 (AAB/split 자동 차단)
"""
import os, zipfile, csv, json
import pandas as pd
from datetime import datetime
from androguard.misc import AnalyzeAPK
from androguard.core.bytecodes import apk


class APKAnalyzer:
    """APK 파일을 분석하는 클래스"""

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.apk_obj = None
        self.dalvik_vm = None
        self.analysis = None
        self.csv_output_dir = None

    # ────────────────────────────────────────────────
    def _looks_like_non_apk(self, path: str) -> bool:
        """APK 구조가 아닌 파일(AAB/split)을 걸러냄"""
        try:
            with zipfile.ZipFile(path, 'r') as z:
                names = set(z.namelist())
            return 'AndroidManifest.xml' not in names
        except Exception:
            return True

    def _make_json_serializable(self, obj):
        if obj is None:
            return None
        elif isinstance(obj, (str, int, float, bool)):
            return obj
        elif isinstance(obj, (list, tuple)):
            return [self._make_json_serializable(o) for o in obj]
        elif isinstance(obj, dict):
            return {str(k): self._make_json_serializable(v) for k, v in obj.items()}
        else:
            return str(obj)

    # ────────────────────────────────────────────────
    def analyze(self):
        """APK 분석 (aapt 불필요)"""
        try:
            if self._looks_like_non_apk(self.apk_path):
                return {
                    "status": "failed",
                    "error": "Not a valid APK (AAB/split likely). Please upload a normal .apk."
                }

            # 1️⃣ Androguard로 분석
            a, d, dx = AnalyzeAPK(self.apk_path)
            self.apk_obj, self.dalvik_vm, self.analysis = a, d, dx

            # AnalyzeAPK가 값이 비정상이면 apk.APK()로 폴백
            pkg = self.apk_obj.get_package()
            perms = list(self.apk_obj.get_permissions() or [])
            if not pkg and not perms:
                self.apk_obj = apk.APK(self.apk_path)
                perms = list(self.apk_obj.get_permissions() or [])

            result = {
                "basic_info": self._extract_basic_info(),
                "permissions": perms,
                "activities": self._extract_activities(),
                "services": self._extract_services(),
                "receivers": self._extract_receivers(),
                "api_calls": self._extract_api_calls(),
                "security_analysis": self._analyze_security(),
                "status": "completed",
            }
            return self._make_json_serializable(result)

        except Exception as e:
            return {"status": "failed", "error": f"AnalyzeAPK failed: {e}"}

    # ────────────────────────────────────────────────
    def _extract_basic_info(self):
        try:
            return self._make_json_serializable({
                "package_name": self.apk_obj.get_package(),
                "version_name": self.apk_obj.get_androidversion_name(),
                "version_code": str(self.apk_obj.get_androidversion_code()),
                "min_sdk": str(self.apk_obj.get_min_sdk_version()),
                "target_sdk": str(self.apk_obj.get_target_sdk_version()),
                "app_name": self.apk_obj.get_app_name(),
                "main_activity": self.apk_obj.get_main_activity(),
            })
        except Exception as e:
            return {"error": str(e)}

    def _extract_activities(self):
        try:
            return self._make_json_serializable(self.apk_obj.get_activities() or [])
        except Exception:
            return []

    def _extract_services(self):
        try:
            return self._make_json_serializable(self.apk_obj.get_services() or [])
        except Exception:
            return []

    def _extract_receivers(self):
        try:
            return self._make_json_serializable(self.apk_obj.get_receivers() or [])
        except Exception:
            return []

    def _extract_api_calls(self):
        try:
            if not self.analysis:
                return []
            apis = []
            risky = [
                'Ljava/lang/Runtime;->exec',
                'Landroid/telephony/SmsManager;->sendTextMessage',
                'Landroid/location/LocationManager;->requestLocationUpdates',
            ]
            for m in self.analysis.get_methods():
                full = f"{m.get_method().get_class_name()}->{m.get_method().get_name()}"
                if any(r in full for r in risky):
                    apis.append(full)
            return self._make_json_serializable(apis)
        except Exception:
            return []

    def _analyze_security(self):
        try:
            perms = self.apk_obj.get_permissions() or []
            issues = []
            danger = [
                "android.permission.SEND_SMS",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
            ]
            for p in perms:
                if p in danger:
                    issues.append({
                        "permission": p,
                        "severity": "high",
                        "description": f"위험 권한 사용: {p}",
                    })
            return {
                "issues": issues,
                "total_issues": len(issues)
            }
        except Exception as e:
            return {"error": str(e)}

    # ────────────────────────────────────────────────
    def analyze_with_csv_export(self, csv_output_dir=None):
        try:
            res = self.analyze()
            if res.get("status") != "completed":
                return res

            if not csv_output_dir:
                csv_output_dir = os.path.join(os.path.dirname(self.apk_path), "analysis_csv")
            os.makedirs(csv_output_dir, exist_ok=True)
            self.csv_output_dir = csv_output_dir

            csvs = []
            # 간단히 permissions만 CSV 저장
            csv_path = os.path.join(csv_output_dir, "permissions.csv")
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Permission"])
                for p in res.get("permissions", []):
                    w.writerow([p])
            csvs.append(csv_path)

            res["csv_files"] = csvs
            res["csv_output_dir"] = csv_output_dir
            return res
        except Exception as e:
            return {"status": "failed", "error": str(e)}
