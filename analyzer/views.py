# analyzer/views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib import messages
from django.core.files.storage import default_storage
from django.utils import timezone
from django.conf import settings
import os, time, tempfile
import json
import shutil
from .models import APKAnalysis
from .apk_analyzer import APKAnalyzer
from .policy_analyzer import PolicyAnalyzer
from .policy_ml import PolicyMLAnalyzer
from .comparison_utils import compare_apk_and_policy


# --- 1. 메인 페이지 ---
def index(request):
    return render(request, 'analyzer/index.html')


# --- 2. 업로드 + 분석 ---
def upload_apk(request):
    # GET이면 업로드 페이지 렌더
    if request.method == 'GET':
        return render(request, 'analyzer/index.html')

    # POST 처리
    if request.method == 'POST':
        apk_file = request.FILES.get('apk_file')
        policy_file = request.FILES.get('policy_file')

        print(f"[DEBUG] APK file: {apk_file.name if apk_file else 'None'}, size: {apk_file.size if apk_file else 0}")
        print(f"[DEBUG] Policy file: {policy_file.name if policy_file else 'None'}")

        if not apk_file:
            messages.error(request, 'APK 파일이 필요합니다.')
            return render(request, 'analyzer/index.html')

        # 임시 디렉토리에 업로드 파일 저장
        tmp_dir = tempfile.mkdtemp()
        apk_path = os.path.join(tmp_dir, apk_file.name)
        
        print(f"[DEBUG] Saving APK to: {apk_path}")
        
        with open(apk_path, 'wb+') as dest:
            for chunk in apk_file.chunks():
                dest.write(chunk)

        policy_path = None
        if policy_file:
            policy_path = os.path.join(tmp_dir, policy_file.name)
            print(f"[DEBUG] Saving policy to: {policy_path}")
            with open(policy_path, 'wb+') as dest:
                for chunk in policy_file.chunks():
                    dest.write(chunk)

        # 모델 레코드 생성 (분석 시작 상태)
        print(f"[DEBUG] Creating analysis record...")
        analysis = APKAnalysis.objects.create(
            file_name=apk_file.name,
            file_size=apk_file.size,
            status='analyzing'
        )
        print(f"[DEBUG] Analysis created with ID: {analysis.id}")

        try:
            # APK 분석기 호출 (CSV 출력 포함)
            print(f"[DEBUG] Starting APK analysis...")
            apk_analyzer = APKAnalyzer(apk_path)
            apk_result = apk_analyzer.analyze_with_csv_export()
            print(f"[DEBUG] APK analysis complete, status: {apk_result.get('status')}")

            if apk_result.get('status') == 'failed':
                analysis.status = 'failed'
                analysis.error_message = apk_result.get('error', 'APK 분석 실패')
                analysis.save()
                messages.error(request, 'APK 분석 실패: ' + str(analysis.error_message))
                return redirect('analyzer:analysis_detail', analysis_id=analysis.id)

            # 모델에 분석 결과 저장
            basic = apk_result.get('basic_info', {}) or {}
            analysis.package_name = basic.get('package_name', '')
            analysis.version_name = basic.get('version_name', '')
            analysis.version_code = basic.get('version_code', '')
            analysis.min_sdk = basic.get('min_sdk', '')
            analysis.target_sdk = basic.get('target_sdk', '')

            analysis.permissions = apk_result.get('permissions', [])
            analysis.activities = apk_result.get('activities', [])
            analysis.services = apk_result.get('services', [])
            analysis.receivers = apk_result.get('receivers', [])
            analysis.api_calls = apk_result.get('api_calls', [])
            analysis.security_analysis = apk_result.get('security_analysis', {})
            # Store CSV files into MEDIA_ROOT so they are downloadable via /media/...
            raw_csv_files = apk_result.get('csv_files', []) or []
            media_target_dir = os.path.join(str(settings.MEDIA_ROOT), 'analysis_csv', str(analysis.id))
            try:
                os.makedirs(media_target_dir, exist_ok=True)
            except Exception:
                pass

            copied_basenames = []
            for fpath in raw_csv_files:
                try:
                    if os.path.exists(fpath):
                        dest = os.path.join(media_target_dir, os.path.basename(fpath))
                        shutil.copy2(fpath, dest)
                        copied_basenames.append(os.path.basename(fpath))
                except Exception:
                    # ignore copy failures for individual files
                    pass

            # If copy succeeded use copied basenames, otherwise fall back to basename extraction
            if copied_basenames:
                analysis.csv_files = copied_basenames
                analysis.csv_output_dir = media_target_dir
            else:
                try:
                    csv_basenames = [os.path.basename(p) for p in raw_csv_files]
                except Exception:
                    csv_basenames = raw_csv_files
                analysis.csv_files = csv_basenames
                # keep original output dir if provided
                analysis.csv_output_dir = apk_result.get('csv_output_dir', '')

            # 처리방침 분석
            policy_result = {}
            if policy_file and policy_path:
                try:
                    print(f"[DEBUG] Starting policy analysis...")
                    # Read raw text (prefer .txt)
                    if policy_file.name.lower().endswith('.txt'):
                        with open(policy_path, 'r', encoding='utf-8', errors='ignore') as f:
                            raw_text = f.read()
                    else:
                        with open(policy_path, 'rb') as pf:
                            data = pf.read()
                        raw_text = data.decode('utf-8', errors='ignore')

                    # Classic simple analyzer (keeps existing behavior)
                    pa = PolicyAnalyzer(policy_path)
                    basic_policy = pa.analyze() if hasattr(pa, 'analyze') else {'status': 'failed'}

                    # ML-based analysis 
                    ml = PolicyMLAnalyzer()
                    ml_result = ml.analyze_text(raw_text)

                    # Merge results
                    policy_result = {
                        'raw_summary': basic_policy.get('summary', ml_result.get('summary')),
                        'ml': ml_result,
                        'basic': basic_policy,
                        'status': 'completed'
                    }
                    print(f"[DEBUG] Policy analysis complete")
                except Exception as e:
                    print(f"[ERROR] Policy analysis failed: {e}")
                    import traceback
                    traceback.print_exc()
                    policy_result = {'status': 'failed', 'error': str(e)}

            analysis.policy_result = policy_result

            # APK와 처리방침 비교
            try:
                print(f"[DEBUG] Starting comparison...")
                comparison = compare_apk_and_policy(apk_result, policy_result)
                print(f"[DEBUG] Comparison complete")
            except Exception as e:
                print(f"[ERROR] Comparison failed: {e}")
                import traceback
                traceback.print_exc()
                comparison = {'error': str(e)}
            
            analysis.comparison_result = comparison

            analysis.status = 'completed'
            analysis.analysis_time = timezone.now()
            analysis.save()

            print(f"[DEBUG] Analysis completed successfully, redirecting to detail page")
            messages.success(request, '분석이 완료되었습니다.')
            return redirect('analyzer:analysis_detail', analysis_id=analysis.id)

        except Exception as e:
            # 실패 처리
            print(f"[ERROR] Analysis failed with exception: {e}")
            import traceback
            traceback.print_exc()
            
            analysis.status = 'failed'
            analysis.error_message = str(e)
            analysis.save()
            messages.error(request, '분석 중 오류가 발생했습니다: ' + str(e))
            return redirect('analyzer:analysis_detail', analysis_id=analysis.id)

        finally:
            # 임시 파일 정리
            try:
                for fname in os.listdir(tmp_dir):
                    fp = os.path.join(tmp_dir, fname)
                    try:
                        os.remove(fp)
                    except Exception:
                        pass
                os.rmdir(tmp_dir)
                print(f"[DEBUG] Cleaned up temp directory")
            except Exception:
                pass

    # 다른 메서드일 경우 인덱스로 리디렉트
    return redirect('analyzer:index')


# --- 3. 분석 목록 ---
def analysis_list(request):
    analyses = APKAnalysis.objects.all()
    return render(request, 'analyzer/analysis_list.html', {'analyses': analyses})


# --- 4. 분석 상세 ---
def analysis_detail(request, analysis_id):
    analysis = get_object_or_404(APKAnalysis, id=analysis_id)

    # JSON 필드를 파싱
    try:
        if isinstance(analysis.security_analysis, str):
            analysis.security_analysis = json.loads(analysis.security_analysis)
    except Exception:
        analysis.security_analysis = analysis.security_analysis or {}

    try:
        if isinstance(analysis.api_calls, str):
            analysis.api_calls = json.loads(analysis.api_calls)
    except Exception:
        analysis.api_calls = analysis.api_calls or []

    try:
        if isinstance(analysis.permissions, str):
            analysis.permissions = json.loads(analysis.permissions)
    except Exception:
        analysis.permissions = analysis.permissions or []

    # parse policy_result and comparison_result if stored as strings
    try:
        if isinstance(analysis.policy_result, str):
            analysis.policy_result = json.loads(analysis.policy_result)
    except Exception:
        analysis.policy_result = analysis.policy_result or {}

    try:
        if isinstance(analysis.comparison_result, str):
            analysis.comparison_result = json.loads(analysis.comparison_result)
    except Exception:
        analysis.comparison_result = analysis.comparison_result or {}

    try:
        raw_csvs = analysis.csv_files or []
        csv_display = []
        for p in raw_csvs:
            try:
                # ensure string and take basename
                if isinstance(p, str):
                    csv_display.append(os.path.basename(p))
                else:
                    csv_display.append(os.path.basename(str(p)))
            except Exception:
                csv_display.append(str(p))
    except Exception:
        csv_display = []

    try:
        media_target_dir = os.path.join(str(settings.MEDIA_ROOT), 'analysis_csv', str(analysis.id))
        os.makedirs(media_target_dir, exist_ok=True)
        for p in (raw_csvs or []):
            try:
                if not isinstance(p, str):
                    p = str(p)
                candidates = [p]
                if not os.path.isabs(p) and analysis.csv_output_dir:
                    candidates.append(os.path.join(analysis.csv_output_dir, p))

                for src in candidates:
                    if not src:
                        continue
                    if os.path.exists(src):
                        dest = os.path.join(media_target_dir, os.path.basename(src))
                        if not os.path.exists(dest):
                            try:
                                shutil.copy2(src, dest)
                            except Exception:
                                pass
                        break
            except Exception:
                pass
    except Exception:
        pass

    csv_output_dir_display = ''
    try:
        if analysis.csv_output_dir:
            csv_output_dir_display = analysis.csv_output_dir
        else:
            if raw_csvs:
                first = raw_csvs[0]
                if isinstance(first, str) and (os.path.isabs(first) or ':' in first):
                    csv_output_dir_display = os.path.dirname(first)
    except Exception:
        csv_output_dir_display = analysis.csv_output_dir or ''

    # render correct template (analysis_detail.html)
    return render(request, 'analyzer/analysis_detail.html', {
        'analysis': analysis,
        'csv_files_display': csv_display,
        'csv_output_dir_display': csv_output_dir_display,
    })


def delete_analysis(request, analysis_id):
    """Delete an analysis and its CSV output directory (POST only)."""
    if request.method != 'POST':
        return redirect('analyzer:analysis_list')

    analysis = get_object_or_404(APKAnalysis, id=analysis_id)
    # attempt to remove csv output dir if present
    try:
        outdir = analysis.csv_output_dir or ''
        if outdir and os.path.exists(outdir) and os.path.isdir(outdir):
            shutil.rmtree(outdir)
    except Exception:
        # ignore failures to remove files
        pass

    analysis.delete()
    messages.success(request, '분석 결과가 삭제되었습니다.')
    return redirect('analyzer:analysis_list')

# --- 5. 상태 확인 API ---
def analysis_status(request, analysis_id):
    analysis_obj = get_object_or_404(APKAnalysis, id=analysis_id)
    return JsonResponse({
        'status': analysis_obj.status,
        'error_message': analysis_obj.error_message
    })