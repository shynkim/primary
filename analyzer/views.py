from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.utils import timezone
import os
import tempfile
from .models import APKAnalysis
from .apk_analyzer import APKAnalyzer


def index(request):
    """메인 페이지 - APK 업로드 폼"""
    return render(request, 'analyzer/index.html')


def upload_apk(request):
    """APK 파일 업로드 및 분석 시작"""
    if request.method == 'POST':
        apk_file = request.FILES.get('apk_file')
        
        if not apk_file:
            messages.error(request, 'APK 파일을 선택해주세요.')
            return redirect('analyzer:index')
        
        # 파일 확장자 검증
        if not apk_file.name.lower().endswith('.apk'):
            messages.error(request, 'APK 파일만 업로드 가능합니다.')
            return redirect('analyzer:index')
        
        # 파일 크기 검증 (50MB 제한)
        if apk_file.size > 50 * 1024 * 1024:
            messages.error(request, '파일 크기는 50MB를 초과할 수 없습니다.')
            return redirect('analyzer:index')
        
        try:
            # APKAnalysis 객체 생성
            analysis_obj = APKAnalysis.objects.create(
                file_name=apk_file.name,
                file_size=apk_file.size,
                status='pending'
            )
            
            # 임시 파일로 저장
            temp_path = default_storage.save(f'temp/{apk_file.name}', ContentFile(apk_file.read()))
            full_path = default_storage.path(temp_path)
            
            # 분석 시작
            analysis_obj.status = 'analyzing'
            analysis_obj.save()
            
            # APK 분석 수행 (CSV 내보내기 포함)
            analyzer = APKAnalyzer(full_path)
            # CSV 파일을 media/analysis_csv/ 디렉토리에 저장
            csv_output_dir = os.path.join(default_storage.location, 'analysis_csv', str(analysis_obj.id))
            result = analyzer.analyze_with_csv_export(csv_output_dir)
            
            if result['status'] == 'completed':
                # 분석 결과 저장
                basic_info = result['basic_info']
                analysis_obj.package_name = basic_info.get('package_name', '')
                analysis_obj.version_name = basic_info.get('version_name', '')
                analysis_obj.version_code = basic_info.get('version_code', '')
                analysis_obj.min_sdk = basic_info.get('min_sdk', '')
                analysis_obj.target_sdk = basic_info.get('target_sdk', '')
                
                analysis_obj.permissions = result['permissions']
                analysis_obj.activities = result['activities']
                analysis_obj.services = result['services']
                analysis_obj.receivers = result['receivers']
                analysis_obj.api_calls = result['api_calls']
                analysis_obj.security_analysis = result['security_analysis']
                
                # CSV 파일 정보 저장 (파일명만 추출)
                csv_files = result.get('csv_files', [])
                csv_filenames = [os.path.basename(f) for f in csv_files]
                analysis_obj.csv_files = csv_filenames
                analysis_obj.csv_output_dir = result.get('csv_output_dir', '')
                
                analysis_obj.status = 'completed'
                analysis_obj.analysis_time = timezone.now()
                
            else:
                analysis_obj.status = 'failed'
                analysis_obj.error_message = result.get('error', '알 수 없는 오류가 발생했습니다.')
            
            analysis_obj.save()
            
            # 임시 파일 삭제
            default_storage.delete(temp_path)
            
            return redirect('analyzer:analysis_detail', analysis_id=analysis_obj.id)
            
        except Exception as e:
            messages.error(request, f'분석 중 오류가 발생했습니다: {str(e)}')
            return redirect('analyzer:index')
    
    return redirect('analyzer:index')


def analysis_list(request):
    """분석 결과 목록 페이지"""
    analyses = APKAnalysis.objects.all()
    return render(request, 'analyzer/analysis_list.html', {'analyses': analyses})


def analysis_detail(request, analysis_id):
    """분석 결과 상세 페이지"""
    analysis_obj = get_object_or_404(APKAnalysis, id=analysis_id)
    return render(request, 'analyzer/analysis_detail.html', {'analysis': analysis_obj})


def analysis_status(request, analysis_id):
    """분석 상태 확인 API"""
    analysis_obj = get_object_or_404(APKAnalysis, id=analysis_id)
    return JsonResponse({
        'status': analysis_obj.status,
        'error_message': analysis_obj.error_message
    })
