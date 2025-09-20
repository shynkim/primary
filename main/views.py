from django.conf import settings
from django.shortcuts import render, redirect
from django.http import HttpResponse
import os

def home(request):
    if request.method == "POST" and request.FILES.get("file"):
        uploaded_file = request.FILES["file"]
        save_path = os.path.join(settings.MEDIA_ROOT, uploaded_file.name)

        with open(save_path, "wb+") as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)

        return redirect("success")
    return render(request, "home.html")

def success(request):
    return render(request, "success.html")