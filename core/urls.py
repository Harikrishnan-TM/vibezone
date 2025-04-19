import os
from pathlib import Path
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

from app.views import hello_world

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('app.urls')),
    path('api/hello/', hello_world),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=os.path.join(settings.BASE_DIR, 'core', 'static'))
