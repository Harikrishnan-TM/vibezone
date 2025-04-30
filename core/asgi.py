import os
import django
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.core.asgi import get_asgi_application
from app.routing import websocket_urlpatterns  # Import your WebSocket routes

# Set the settings module for Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()  # Initialize Django

# Main ASGI application
application = ProtocolTypeRouter({
    "http": get_asgi_application(),  # Handles traditional HTTP requests
    "websocket": AuthMiddlewareStack(
        URLRouter(websocket_urlpatterns)  # Handles WebSocket connections
    ),
})
