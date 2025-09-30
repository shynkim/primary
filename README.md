# APK 분석기

Androguard를 기반으로 한 웹 기반 APK 파일 분석 도구입니다. Django 프레임워크를 사용하여 구축되었습니다.

## 주요 기능

- **APK 파일 업로드**: 웹 인터페이스를 통한 APK 파일 업로드
- **기본 정보 분석**: 패키지명, 버전 정보, SDK 버전 등
- **권한 분석**: APK가 요청하는 모든 권한 목록
- **컴포넌트 분석**: 액티비티, 서비스, 리시버 정보
- **보안 분석**: 위험한 권한, API 호출, 보안 설정 검사
- **API 호출 분석**: 위험한 API 호출 패턴 감지

## 설치 및 실행

### 1. 저장소 클론
```bash
git clone <repository-url>
cd apk_analyzer
```

### 2. 가상환경 생성 및 활성화
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
# 또는
venv\Scripts\activate     # Windows
```

### 3. 의존성 설치
```bash
pip install -r requirements.txt
```

### 4. 데이터베이스 마이그레이션
```bash
python manage.py migrate
```

### 5. 개발 서버 실행
```bash
python manage.py runserver
```

브라우저에서 `http://127.0.0.1:8000/`에 접속하여 APK 분석기를 사용할 수 있습니다.

## 사용 방법

1. **APK 업로드**: 메인 페이지에서 APK 파일을 드래그 앤 드롭하거나 파일 선택 버튼을 클릭
2. **분석 대기**: 업로드된 APK 파일이 자동으로 분석됩니다
3. **결과 확인**: 분석 완료 후 상세 결과를 확인할 수 있습니다
4. **분석 목록**: 이전에 분석한 APK들의 목록을 확인할 수 있습니다

## 기술 스택

- **Backend**: Django 4.2.7
- **APK 분석**: Androguard
- **Frontend**: Bootstrap 5, Font Awesome
- **Database**: SQLite (개발용)

## 프로젝트 구조

```
apk_analyzer/
├── analyzer/                 # 메인 앱
│   ├── models.py            # 데이터베이스 모델
│   ├── views.py             # 뷰 함수
│   ├── urls.py              # URL 패턴
│   ├── apk_analyzer.py      # APK 분석 로직
│   └── templates/           # HTML 템플릿
├── apk_analyzer/            # 프로젝트 설정
│   ├── settings.py          # Django 설정
│   └── urls.py              # 메인 URL 설정
└── manage.py                # Django 관리 스크립트
```

## 보안 분석 기능

### 위험한 권한 감지
- SMS 전송/수신 권한
- 오디오 녹음 권한
- 카메라 접근 권한
- 위치 정보 접근 권한
- 연락처 접근 권한
- 통화 기록 접근 권한

### API 호출 분석
- Runtime.exec() 호출
- SMS 전송 API
- 위치 서비스 API
- 네트워크 연결 API
- 암호화 관련 API

### 보안 설정 검사
- 디버그 가능 여부
- 백업 허용 여부
- 네트워크 보안 정책 설정

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 기여하기

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 문의

프로젝트에 대한 문의사항이 있으시면 이슈를 생성해 주세요.
