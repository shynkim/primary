from django.shortcuts import render, redirect
from django.conf import settings
import os

def home(request):
    if request.method == "POST":
        # 입력값 저장
        request.session["policy_text"] = request.POST.get("policy_text")

        if "apk_file" in request.FILES:
            apk_file = request.FILES["apk_file"]
            save_path = os.path.join(settings.MEDIA_ROOT, apk_file.name)
            with open(save_path, "wb+") as destination:
                for chunk in apk_file.chunks():
                    destination.write(chunk)
            request.session["uploaded_file"] = apk_file.name

        # ✅ redirect로 /result URL로 이동
        return redirect("result")

    return render(request, "home.html")


def result(request):
    uploaded_file = request.session.get("uploaded_file")
    policy_text = request.session.get("policy_text")

    return render(request, "result.html", {
        "uploaded_file": uploaded_file,
        "policy_text": policy_text,
    })