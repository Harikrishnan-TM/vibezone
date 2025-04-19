from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    # Online user updates (for listing users in real-time)
    re_path(r'^ws/online-users/$', consumers.OnlineUserConsumer.as_asgi()),

    # Per-user WebSocket for calls
    re_path(r'^ws/call/(?P<username>\w+)/$', consumers.CallConsumer.as_asgi()),
]
