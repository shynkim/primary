"""
APK 파일 분석을 위한 Androguard 기반 분석기
"""
import os
import tempfile
import zipfile
import json
import csv
import pandas as pd
from datetime import datetime
from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis
from androguard.misc import AnalyzeAPK


class APKAnalyzer:
    """APK 파일을 분석하는 클래스"""
    
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk_obj = None
        self.dalvik_vm = None
        self.analysis = None
        self.csv_output_dir = None
    
    def _make_json_serializable(self, obj):
        """객체를 JSON 직렬화 가능한 형태로 변환"""
        if obj is None:
            return None
        elif isinstance(obj, (str, int, float, bool)):
            return obj
        elif isinstance(obj, (list, tuple)):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {str(key): self._make_json_serializable(value) for key, value in obj.items()}
        else:
            # MUTF8String 및 기타 Androguard 객체들을 문자열로 변환
            return str(obj)
        
    def analyze(self):
        """APK 파일을 분석하고 결과를 반환"""
        try:
            # APK 파일 분석
            self.apk_obj, self.dalvik_vm, self.analysis = AnalyzeAPK(self.apk_path)
            
            # 기본 정보 추출
            basic_info = self._extract_basic_info()
            
            # 권한 정보 추출
            permissions = self._extract_permissions()
            
            # 컴포넌트 정보 추출
            activities = self._extract_activities()
            services = self._extract_services()
            receivers = self._extract_receivers()
            
            # API 호출 정보 추출
            api_calls = self._extract_api_calls()
            
            # 보안 분석
            security_analysis = self._analyze_security()
            
            result = {
                'basic_info': basic_info,
                'permissions': permissions,
                'activities': activities,
                'services': services,
                'receivers': receivers,
                'api_calls': api_calls,
                'security_analysis': security_analysis,
                'status': 'completed'
            }
            
            # 모든 결과를 JSON 직렬화 가능한 형태로 변환
            return self._make_json_serializable(result)
            
        except Exception as e:
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    def _extract_basic_info(self):
        """APK의 기본 정보를 추출"""
        try:
            basic_info = {
                'package_name': self.apk_obj.get_package(),
                'version_name': self.apk_obj.get_androidversion_name(),
                'version_code': str(self.apk_obj.get_androidversion_code()),
                'min_sdk': str(self.apk_obj.get_min_sdk_version()),
                'target_sdk': str(self.apk_obj.get_target_sdk_version()),
                'app_name': self.apk_obj.get_app_name(),
                'main_activity': self.apk_obj.get_main_activity(),
            }
            return self._make_json_serializable(basic_info)
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_permissions(self):
        """권한 정보를 추출"""
        try:
            permissions = self.apk_obj.get_permissions()
            permission_list = list(permissions) if permissions else []
            return self._make_json_serializable(permission_list)
        except Exception as e:
            return []
    
    def _extract_activities(self):
        """액티비티 정보를 추출"""
        try:
            activities = self.apk_obj.get_activities()
            activity_list = []
            
            for activity in activities:
                activity_info = {
                    'name': activity,
                    'exported': self.apk_obj.get_activity(activity).get('exported', False),
                    'intent_filters': []
                }
                
                # Intent filters 추출
                intent_filters = self.apk_obj.get_intent_filters('activity', activity)
                if intent_filters:
                    for intent_filter in intent_filters:
                        filter_info = {
                            'actions': intent_filter.get('action', []),
                            'categories': intent_filter.get('category', []),
                            'data': intent_filter.get('data', [])
                        }
                        activity_info['intent_filters'].append(filter_info)
                
                activity_list.append(activity_info)
            
            return self._make_json_serializable(activity_list)
        except Exception as e:
            return []
    
    def _extract_services(self):
        """서비스 정보를 추출"""
        try:
            services = self.apk_obj.get_services()
            service_list = []
            
            for service in services:
                service_info = {
                    'name': service,
                    'exported': self.apk_obj.get_service(service).get('exported', False),
                    'intent_filters': []
                }
                
                # Intent filters 추출
                intent_filters = self.apk_obj.get_intent_filters('service', service)
                if intent_filters:
                    for intent_filter in intent_filters:
                        filter_info = {
                            'actions': intent_filter.get('action', []),
                            'categories': intent_filter.get('category', []),
                            'data': intent_filter.get('data', [])
                        }
                        service_info['intent_filters'].append(filter_info)
                
                service_list.append(service_info)
            
            return self._make_json_serializable(service_list)
        except Exception as e:
            return []
    
    def _extract_receivers(self):
        """리시버 정보를 추출"""
        try:
            receivers = self.apk_obj.get_receivers()
            receiver_list = []
            
            for receiver in receivers:
                receiver_info = {
                    'name': receiver,
                    'exported': self.apk_obj.get_receiver(receiver).get('exported', False),
                    'intent_filters': []
                }
                
                # Intent filters 추출
                intent_filters = self.apk_obj.get_intent_filters('receiver', receiver)
                if intent_filters:
                    for intent_filter in intent_filters:
                        filter_info = {
                            'actions': intent_filter.get('action', []),
                            'categories': intent_filter.get('category', []),
                            'data': intent_filter.get('data', [])
                        }
                        receiver_info['intent_filters'].append(filter_info)
                
                receiver_list.append(receiver_info)
            
            return self._make_json_serializable(receiver_list)
        except Exception as e:
            return []
    
    def _extract_api_calls(self):
        """API 호출 정보를 추출"""
        try:
            api_calls = []
            
            if self.analysis:
                # 위험한 API 호출 패턴 검사
                dangerous_apis = [
                    'Ljava/lang/Runtime;->exec',
                    'Landroid/telephony/SmsManager;->sendTextMessage',
                    'Landroid/location/LocationManager;->requestLocationUpdates',
                    'Landroid/content/Context;->sendBroadcast',
                    'Ljava/net/URL;->openConnection',
                    'Ljavax/crypto/Cipher;->getInstance',
                ]
                
                for method in self.analysis.get_methods():
                    method_name = method.get_method().get_name()
                    class_name = method.get_method().get_class_name()
                    full_name = f"{class_name}->{method_name}"
                    
                    for dangerous_api in dangerous_apis:
                        if dangerous_api in full_name:
                            api_calls.append({
                                'api': full_name,
                                'class': class_name,
                                'method': method_name,
                                'risk_level': 'high' if 'exec' in full_name or 'sendTextMessage' in full_name else 'medium'
                            })
                            break
            
            return self._make_json_serializable(api_calls)
        except Exception as e:
            return []
    
    def _analyze_security(self):
        """보안 분석 수행"""
        try:
            security_issues = []
            
            # 위험한 권한 검사
            dangerous_permissions = [
                'android.permission.SEND_SMS',
                'android.permission.READ_SMS',
                'android.permission.RECORD_AUDIO',
                'android.permission.CAMERA',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.ACCESS_COARSE_LOCATION',
                'android.permission.READ_CONTACTS',
                'android.permission.WRITE_CONTACTS',
                'android.permission.READ_CALL_LOG',
                'android.permission.WRITE_CALL_LOG',
            ]
            
            app_permissions = self.apk_obj.get_permissions()
            for permission in dangerous_permissions:
                if permission in app_permissions:
                    security_issues.append({
                        'type': 'dangerous_permission',
                        'permission': permission,
                        'severity': 'high',
                        'description': f'위험한 권한 사용: {permission}'
                    })
            
            # 디버그 가능 여부 검사
            if self.apk_obj.is_debuggable():
                security_issues.append({
                    'type': 'debuggable',
                    'severity': 'medium',
                    'description': '앱이 디버그 가능하도록 설정됨'
                })
            
            # 백업 허용 여부 검사
            if self.apk_obj.is_allow_backup():
                security_issues.append({
                    'type': 'allow_backup',
                    'severity': 'medium',
                    'description': '앱 데이터 백업이 허용됨'
                })
            
            # 네트워크 보안 정책 검사
            if not self.apk_obj.is_network_security_config():
                security_issues.append({
                    'type': 'network_security',
                    'severity': 'low',
                    'description': '네트워크 보안 정책이 설정되지 않음'
                })
            
            security_result = {
                'issues': security_issues,
                'total_issues': len(security_issues),
                'high_severity': len([i for i in security_issues if i.get('severity') == 'high']),
                'medium_severity': len([i for i in security_issues if i.get('severity') == 'medium']),
                'low_severity': len([i for i in security_issues if i.get('severity') == 'low']),
            }
            return self._make_json_serializable(security_result)
            
        except Exception as e:
            error_result = {
                'error': str(e),
                'issues': [],
                'total_issues': 0
            }
            return self._make_json_serializable(error_result)
    
    def _save_permissions_to_csv(self, permissions, output_dir):
        """권한 목록을 CSV 파일로 저장"""
        try:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            csv_path = os.path.join(output_dir, 'permissions.csv')
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Permission'])  # 헤더
                
                for permission in permissions:
                    writer.writerow([permission])
            
            return csv_path
        except Exception as e:
            print(f"권한 CSV 저장 중 오류 발생: {e}")
            return None
    
    def _save_analysis_to_csv(self, analysis_data, output_dir):
        """전체 분석 결과를 여러 CSV 파일로 저장"""
        try:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            saved_files = []
            
            # 1. 기본 정보 CSV
            if 'basic_info' in analysis_data:
                basic_info_path = os.path.join(output_dir, 'basic_info.csv')
                basic_df = pd.DataFrame([analysis_data['basic_info']])
                basic_df.to_csv(basic_info_path, index=False, encoding='utf-8')
                saved_files.append(basic_info_path)
            
            # 2. 권한 목록 CSV
            if 'permissions' in analysis_data:
                permissions_path = self._save_permissions_to_csv(analysis_data['permissions'], output_dir)
                if permissions_path:
                    saved_files.append(permissions_path)
            
            # 3. 액티비티 정보 CSV
            if 'activities' in analysis_data and analysis_data['activities']:
                activities_path = os.path.join(output_dir, 'activities.csv')
                activities_df = pd.DataFrame(analysis_data['activities'])
                activities_df.to_csv(activities_path, index=False, encoding='utf-8')
                saved_files.append(activities_path)
            
            # 4. 서비스 정보 CSV
            if 'services' in analysis_data and analysis_data['services']:
                services_path = os.path.join(output_dir, 'services.csv')
                services_df = pd.DataFrame(analysis_data['services'])
                services_df.to_csv(services_path, index=False, encoding='utf-8')
                saved_files.append(services_path)
            
            # 5. 리시버 정보 CSV
            if 'receivers' in analysis_data and analysis_data['receivers']:
                receivers_path = os.path.join(output_dir, 'receivers.csv')
                receivers_df = pd.DataFrame(analysis_data['receivers'])
                receivers_df.to_csv(receivers_path, index=False, encoding='utf-8')
                saved_files.append(receivers_path)
            
            # 6. API 호출 정보 CSV
            if 'api_calls' in analysis_data and analysis_data['api_calls']:
                api_calls_path = os.path.join(output_dir, 'api_calls.csv')
                api_calls_df = pd.DataFrame(analysis_data['api_calls'])
                api_calls_df.to_csv(api_calls_path, index=False, encoding='utf-8')
                saved_files.append(api_calls_path)
            
            # 7. 보안 분석 결과 CSV
            if 'security_analysis' in analysis_data and 'issues' in analysis_data['security_analysis']:
                security_path = os.path.join(output_dir, 'security_analysis.csv')
                security_df = pd.DataFrame(analysis_data['security_analysis']['issues'])
                security_df.to_csv(security_path, index=False, encoding='utf-8')
                saved_files.append(security_path)
            
            return saved_files
            
        except Exception as e:
            print(f"CSV 저장 중 오류 발생: {e}")
            return []
    
    def analyze_with_csv_export(self, csv_output_dir=None):
        """APK 분석 후 결과를 JSON과 CSV 형태로 모두 저장"""
        try:
            # 기본 분석 수행
            analysis_result = self.analyze()
            
            if analysis_result.get('status') == 'failed':
                return analysis_result
            
            # CSV 출력 디렉토리 설정
            if csv_output_dir is None:
                csv_output_dir = os.path.join(os.path.dirname(self.apk_path), 'analysis_csv')
            
            self.csv_output_dir = csv_output_dir
            
            # CSV 파일들 저장
            saved_csv_files = self._save_analysis_to_csv(analysis_result, csv_output_dir)
            
            # 결과에 CSV 파일 경로 정보 추가
            analysis_result['csv_files'] = saved_csv_files
            analysis_result['csv_output_dir'] = csv_output_dir
            
            return analysis_result
            
        except Exception as e:
            return {
                'status': 'failed',
                'error': str(e)
            }

