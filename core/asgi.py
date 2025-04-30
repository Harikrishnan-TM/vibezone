


import os
import django
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.core.asgi import get_asgi_application
from app.sockets import socketio  # Import your Socket.IO instance
from app.routing import websocket_urlpatterns  # Import WebSocket URL routing

# Set the settings module to 'core.settings' since that's where your settings.py is located
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()  # Set up Django before routing

# Create the application
application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(  # Optional but recommended
        URLRouter(websocket_urlpatterns)
    ),
})

# Integrating Socket.IO with Channels
from socketio import ASGIApp

# Attach the Socket.IO server to the ASGI application, making it handle WebSockets
application = ASGIApp(socketio, other_asgi_app=application)

