from django.db import models
from django.utils import timezone


class APKAnalysis(models.Model):
    """
    APK 분석 및 처리방침(Policy) 예측 결과를 하나의 레코드로 보관하는 모델.
    - 두 파일(model.py / models.py)의 내용을 병합: 필수 메타/헬퍼 + ML/CSV/보안/메타 필드 일원화
    """

    # ── 상태 관리 ─────────────────────────────────────────────────────────────
    STATUS_PENDING = "pending"
    STATUS_ANALYZING = "analyzing"
    STATUS_COMPLETED = "completed"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_PENDING, "분석 대기중"),
        (STATUS_ANALYZING, "분석 중"),
        (STATUS_COMPLETED, "분석 완료"),
        (STATUS_FAILED, "분석 실패"),
    ]

    # ── 업로드/메타 ────────────────────────────────────────────────────────────
    file_name = models.CharField(max_length=255, verbose_name="파일명")
    file_size = models.BigIntegerField(blank=True, null=True, verbose_name="파일 크기")
    upload_time = models.DateTimeField(auto_now_add=True, verbose_name="업로드 시간")
    analysis_time = models.DateTimeField(blank=True, null=True, verbose_name="분석 시간")
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        verbose_name="상태",
    )
    error_message = models.TextField(blank=True, null=True, verbose_name="오류 메시지")

    # ── APK 기본 정보 ─────────────────────────────────────────────────────────
    package_name = models.CharField(max_length=255, blank=True, null=True, verbose_name="패키지명")
    version_name = models.CharField(max_length=100, blank=True, null=True, verbose_name="버전명")
    # 두 버전(50/100) 중 여유 있게 100으로 통일
    version_code = models.CharField(max_length=100, blank=True, null=True, verbose_name="버전 코드")
    # 길이 제한 과도함 방지: 50으로 통일
    min_sdk = models.CharField(max_length=50, blank=True, null=True, verbose_name="최소 SDK")
    target_sdk = models.CharField(max_length=50, blank=True, null=True, verbose_name="타겟 SDK")

    # ── 구조/권한/API ─────────────────────────────────────────────────────────
    permissions = models.JSONField(default=list, blank=True, null=True, verbose_name="권한 목록")
    activities = models.JSONField(default=list, blank=True, null=True, verbose_name="액티비티 목록")
    services = models.JSONField(default=list, blank=True, null=True, verbose_name="서비스 목록")
    receivers = models.JSONField(default=list, blank=True, null=True, verbose_name="리시버 목록")
    api_calls = models.JSONField(default=list, blank=True, null=True, verbose_name="API 호출 목록")
    security_analysis = models.JSONField(default=dict, blank=True, null=True, verbose_name="보안 분석 결과")

    # ── CSV 산출물 ────────────────────────────────────────────────────────────
    csv_files = models.JSONField(default=list, blank=True, null=True, verbose_name="CSV 파일 목록")
    # 경로 길이 제한을 피하려면 TextField가 안전
    csv_output_dir = models.TextField(blank=True, null=True, verbose_name="CSV 출력 디렉토리")

    # ── ML/정책 예측 결과(추가 확장 필드 포함) ──────────────────────────────────
    # 전체 문서 레벨 예측 라벨(간단 요약)
    policy_labels = models.JSONField(default=list, blank=True, null=True, verbose_name="처리방침 예측 라벨")
    # 문장 단위 라벨링 결과(세부)
    policy_sentence_labels = models.JSONField(default=list, blank=True, null=True, verbose_name="문장 단위 라벨")
    # 프런트에서 사용하는 아이템화된 결과(태그/근거 등)
    policy_items = models.JSONField(default=list, blank=True, null=True, verbose_name="정책 항목 요약")
    policy_items_detail = models.JSONField(default=list, blank=True, null=True, verbose_name="정책 항목 상세")
    # APK 권한 vs 정책 라벨 비교 결과
    comparison = models.JSONField(default=dict, blank=True, null=True, verbose_name="APK × 정책 비교")

    class Meta:
        verbose_name = "APK 분석"
        verbose_name_plural = "APK 분석 목록"
        ordering = ["-upload_time"]
        indexes = [
            models.Index(fields=["file_name"]),
            models.Index(fields=["package_name"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self) -> str:
        return f"{self.file_name} - {self.get_status_display()}"

    # ── 편의 메서드 ───────────────────────────────────────────────────────────
    def get_permissions_display(self) -> str:
        """권한 목록을 읽기 쉬운 문자열로 반환"""
        if isinstance(self.permissions, list):
            return ", ".join(self.permissions)
        return str(self.permissions) if self.permissions is not None else ""

    def get_activities_count(self) -> int:
        """액티비티 개수 반환"""
        return len(self.activities) if isinstance(self.activities, list) else 0

    def get_services_count(self) -> int:
        """서비스 개수 반환"""
        return len(self.services) if isinstance(self.services, list) else 0

    def mark_analyzing(self):
        self.status = self.STATUS_ANALYZING
        self.analysis_time = timezone.now()
        self.save(update_fields=["status", "analysis_time"])

    def mark_completed(self):
        self.status = self.STATUS_COMPLETED
        if not self.analysis_time:
            self.analysis_time = timezone.now()
        self.save(update_fields=["status", "analysis_time"])

    def mark_failed(self, message: str = ""):
        self.status = self.STATUS_FAILED
        self.error_message = message
        self.analysis_time = timezone.now()
        self.save(update_fields=["status", "error_message", "analysis_time"])
