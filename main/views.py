from django.conf import settings
from django.shortcuts import render
import os

def home(request):
    uploaded_file = None

    # 파일 업로드만 처리
    if request.method == "POST" and "apk_file" in request.FILES:
        apk_file = request.FILES["apk_file"]

        # 파일 저장
        save_path = os.path.join(settings.MEDIA_ROOT, apk_file.name)
        with open(save_path, "wb+") as destination:
            for chunk in apk_file.chunks():
                destination.write(chunk)

        uploaded_file = apk_file.name

    return render(request, "home.html", {"uploaded_file": uploaded_file})


def success(request):
    if request.method == "POST":
        policy_text = request.POST.get("policy_text")
        return render(request, "success.html", {"policy_text": policy_text})
    return render(request, "success.html")