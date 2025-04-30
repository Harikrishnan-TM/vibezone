# sockets.py

import socketio

# Create a Socket.IO server instance
socketio = socketio.Server(cors_allowed_origins='*')

# (Optional) Example event handlers
@socketio.event
def connect(sid, environ):
    print(f"Client {sid} connected")

@socketio.event
def disconnect(sid):
    print(f"Client {sid} disconnected")

@socketio.event
def refresh_users(sid, data):
    print(f"Received refresh_users event with data: {data}")
