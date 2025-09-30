from django.urls import path
from . import views

app_name = 'analyzer'

urlpatterns = [
    path('', views.index, name='index'),
    path('upload/', views.upload_apk, name='upload_apk'),
    path('list/', views.analysis_list, name='analysis_list'),
    path('detail/<int:analysis_id>/', views.analysis_detail, name='analysis_detail'),
    path('status/<int:analysis_id>/', views.analysis_status, name='analysis_status'),
]

