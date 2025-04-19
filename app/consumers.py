import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth import get_user_model
from asgiref.sync import sync_to_async

# Set up logging
logger = logging.getLogger(__name__)

class CallConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.username = self.scope['url_route']['kwargs']['username']
        self.room_group_name = f"user_{self.username}"

        # Log the connection
        logger.info(f"User {self.username} connected to room {self.room_group_name}")

        # Join the user's private channel group
        try:
            await self.channel_layer.group_add(
                self.room_group_name,
                self.channel_name
            )
            await self.accept()
        except Exception as e:
            logger.error(f"Failed to join group {self.room_group_name} for {self.username}: {e}")
            await self.close()

    async def disconnect(self, close_code):
        # Log the disconnection
        logger.info(f"User {self.username} disconnected")

        # Leave user's group when disconnected
        try:
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
        except Exception as e:
            logger.error(f"Error leaving group {self.room_group_name} for {self.username}: {e}")

    @sync_to_async
    def set_user_busy(self, username, busy=True):
        User = get_user_model()
        try:
            user = User.objects.get(username=username)
            user.is_busy = busy
            user.save()
            logger.info(f"User {username} status updated to {'busy' if busy else 'available'}")
        except User.DoesNotExist:
            logger.error(f"User {username} not found")
            pass

    async def receive(self, text_data):
        data = json.loads(text_data)
        message_type = data.get('type')
        target_user = data.get('target')

        if message_type == 'offer' and target_user:
            # Ensure the target user exists before marking them as busy
            if await self.user_exists(target_user):
                await self.set_user_busy(self.username, True)
                await self.set_user_busy(target_user, True)
                logger.info(f"Call offer sent from {self.username} to {target_user}")
            else:
                logger.error(f"Target user {target_user} does not exist")

        elif message_type == 'end_call' and target_user:
            await self.set_user_busy(self.username, False)
            await self.set_user_busy(target_user, False)

            # Notify the target to end the call
            try:
                await self.channel_layer.group_send(
                    f"user_{target_user}",
                    {
                        'type': 'call.ended'
                    }
                )
                logger.info(f"Call ended notification sent to {target_user}")
            except Exception as e:
                logger.error(f"Failed to notify {target_user} about call ending: {e}")

    async def call_ended(self, event):
        await self.send(text_data=json.dumps({
            'type': 'end_call'
        }))

    @sync_to_async
    def user_exists(self, username):
        """Check if a user exists"""
        User = get_user_model()
        return User.objects.filter(username=username).exists()

class OnlineUserConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Log the connection
        logger.info(f"User connected to online users group")
        
        # Add user to the online group
        try:
            await self.channel_layer.group_add("online_users", self.channel_name)
            await self.accept()
        except Exception as e:
            logger.error(f"Failed to join online users group: {e}")
            await self.close()

    async def disconnect(self, close_code):
        # Log the disconnection
        logger.info(f"User disconnected from online users group")

        try:
            await self.channel_layer.group_discard("online_users", self.channel_name)
        except Exception as e:
            logger.error(f"Failed to leave online users group: {e}")

    async def receive(self, text_data):
        data = json.loads(text_data)
        if data.get("type") == "call_update":
            # Log the received call update
            logger.info(f"Call update received: {data.get('payload')}")

            try:
                await self.channel_layer.group_send(
                    "online_users",
                    {
                        "type": "broadcast.call",
                        "payload": data.get("payload")
                    }
                )
            except Exception as e:
                logger.error(f"Failed to broadcast call update: {e}")

    async def broadcast_call(self, event):
        await self.send(text_data=json.dumps({
            "type": "call",
            "payload": event.get("payload")
        }))
