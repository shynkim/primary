from django.db import models
import json

class APKAnalysis(models.Model):
    policy_sentence_labels = models.JSONField(default=list, blank=True)  # ← 핵심
    """APK 파일 분석 결과를 저장하는 모델"""
    
    STATUS_CHOICES = [
        ('pending', '분석 대기중'),
        ('analyzing', '분석 중'),
        ('completed', '분석 완료'),
        ('failed', '분석 실패'),
    ]
    
    # 기본 정보
    file_name = models.CharField(max_length=255, verbose_name="파일명")
    file_size = models.BigIntegerField(verbose_name="파일 크기")
    upload_time = models.DateTimeField(auto_now_add=True, verbose_name="업로드 시간")
    analysis_time = models.DateTimeField(null=True, blank=True, verbose_name="분석 시간")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', verbose_name="상태")
    
    # APK 기본 정보
    package_name = models.CharField(max_length=255, blank=True, verbose_name="패키지명")
    version_name = models.CharField(max_length=100, blank=True, verbose_name="버전명")
    version_code = models.CharField(max_length=50, blank=True, verbose_name="버전 코드")
    min_sdk = models.CharField(max_length=20, blank=True, verbose_name="최소 SDK")
    target_sdk = models.CharField(max_length=20, blank=True, verbose_name="타겟 SDK")
    
    # 권한 정보
    permissions = models.JSONField(default=list, verbose_name="권한 목록")
    
    # 액티비티 정보
    activities = models.JSONField(default=list, verbose_name="액티비티 목록")
    
    # 서비스 정보
    services = models.JSONField(default=list, verbose_name="서비스 목록")
    
    # 리시버 정보
    receivers = models.JSONField(default=list, verbose_name="리시버 목록")
    
    # API 호출 정보
    api_calls = models.JSONField(default=list, verbose_name="API 호출 목록")
    
    # 보안 분석 결과
    security_analysis = models.JSONField(default=dict, verbose_name="보안 분석 결과")
    
    # CSV 파일 정보
    csv_files = models.JSONField(default=list, verbose_name="CSV 파일 목록")
    csv_output_dir = models.CharField(max_length=500, blank=True, verbose_name="CSV 출력 디렉토리")
    
    # 오류 메시지
    error_message = models.TextField(blank=True, verbose_name="오류 메시지")
    
    # 정책 처리방침 예측 라벨
    policy_labels = models.JSONField(default=list, verbose_name="처리방침 예측 라벨")
    
    class Meta:
        verbose_name = "APK 분석"
        verbose_name_plural = "APK 분석 목록"
        ordering = ['-upload_time']
    
    def __str__(self):
        return f"{self.file_name} - {self.get_status_display()}"
    
    def get_permissions_display(self):
        """권한 목록을 읽기 쉬운 형태로 반환"""
        if isinstance(self.permissions, list):
            return ', '.join(self.permissions)
        return str(self.permissions)
    
    def get_activities_count(self):
        """액티비티 개수 반환"""
        if isinstance(self.activities, list):
            return len(self.activities)
        return 0
    
    def get_services_count(self):
        """서비스 개수 반환"""
        if isinstance(self.services, list):
            return len(self.services)
        return 0
