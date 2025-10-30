# analyzer/urls.py
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views

app_name = 'analyzer'

urlpatterns = [
    path('', views.index, name='index'),

    # 업로드/분석
    path('upload/', views.upload_apk, name='upload_apk'),
    path('list/', views.analysis_list, name='analysis_list'),
    path('detail/<int:analysis_id>/', views.analysis_detail, name='analysis_detail'),
    path('status/<int:analysis_id>/', views.analysis_status, name='analysis_status'),

    # ✅ 정책 텍스트 예측 API (index.html의 JS fetch에서 사용)
    path('policy/predict/', views.policy_predict_api, name='policy_predict_api'),
]

# 개발 환경에서 media 파일 서빙
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
