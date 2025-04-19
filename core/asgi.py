import os
import django
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.core.asgi import get_asgi_application
from app.routing import websocket_urlpatterns  # Make sure to import your routing here

# Set the settings module to 'core.settings' since that's where your settings.py is located
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()  # Set up Django before routing

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(  # Optional but recommended
        URLRouter(websocket_urlpatterns)
    ),
})
