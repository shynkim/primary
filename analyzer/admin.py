from django.contrib import admin
from .models import APKAnalysis

@admin.register(APKAnalysis)
class APKAnalysisAdmin(admin.ModelAdmin):
    list_display = ['file_name', 'package_name', 'version_name', 'status', 'upload_time']
    list_filter = ['status', 'upload_time']
    search_fields = ['file_name', 'package_name']
    readonly_fields = ['upload_time', 'analysis_time', 'file_size']
    
    fieldsets = (
        ('기본 정보', {
            'fields': ('file_name', 'file_size', 'upload_time', 'analysis_time', 'status')
        }),
        ('APK 정보', {
            'fields': ('package_name', 'version_name', 'version_code', 'min_sdk', 'target_sdk')
        }),
        ('분석 결과', {
            'fields': ('permissions', 'activities', 'services', 'receivers', 'api_calls', 'security_analysis'),
            'classes': ('collapse',)
        }),
        ('오류 정보', {
            'fields': ('error_message',),
            'classes': ('collapse',)
        }),
    )
