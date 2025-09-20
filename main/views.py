from django.http import HttpResponse
from django.shortcuts import render

def home(request):
    if request.method == "POST" and request.FILES.get("file"):
        uploaded_file = request.FILES["file"]
        with open(f"media/{uploaded_file.name}", "wb+") as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)
        return HttpResponse("업로드 성공 🎉")
    return render(request, "home.html")