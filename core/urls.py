import os
from pathlib import Path
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse  # ✅ Add this ok ok ok



from app.views import hello_world

# ✅ Add a simple health check view
def health_check(request):
    return JsonResponse({"status": "ok"})

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('app.urls')),
    path('api/hello/', hello_world),
    path('health', health_check),  # ✅ This line fixes the issue
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=os.path.join(settings.BASE_DIR, 'core', 'static'))
