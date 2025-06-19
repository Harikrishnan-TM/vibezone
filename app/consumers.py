import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth import get_user_model
from asgiref.sync import sync_to_async

logger = logging.getLogger(__name__)
User = get_user_model()


class CallConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.username = self.scope['url_route']['kwargs']['username']
        self.room_group_name = f"user_{self.username}"

        logger.info(f"User {self.username} connected to room {self.room_group_name}")

        try:
            await self.channel_layer.group_add(self.room_group_name, self.channel_name)
            await self.accept()
        except Exception as e:
            logger.error(f"Failed to join group {self.room_group_name}: {e}")
            await self.close()

    async def disconnect(self, close_code):
        logger.info(f"User {self.username} disconnected")
        try:
            await self.channel_layer.group_discard(self.room_group_name, self.channel_name)
        except Exception as e:
            logger.error(f"Error leaving group {self.room_group_name}: {e}")

    @sync_to_async
    def set_user_busy(self, username, busy=True, target_username=None):
        try:
            user = User.objects.get(username=username)
            user.is_busy = busy

            if target_username:
                try:
                    target = User.objects.get(username=target_username)
                    user.in_call_with = target
                except User.DoesNotExist:
                    user.in_call_with = None
            else:
                user.in_call_with = None

            user.save()
            logger.info(f"{username} set to {'busy' if busy else 'available'} (in call with: {target_username})")
        except User.DoesNotExist:
            logger.error(f"User {username} not found")

    @sync_to_async
    def get_wallet_balance(self, username):
        try:
            user = User.objects.get(username=username)
            return user.wallet_coins
        except User.DoesNotExist:
            logger.error(f"Wallet lookup failed for {username}")
            return 0

    @sync_to_async
    def user_exists(self, username):
        return User.objects.filter(username=username).exists()

    @sync_to_async
    def create_call_history(self, caller_username, receiver_username):
        from .models import CallHistory
        try:
            caller = User.objects.get(username=caller_username)
            receiver = User.objects.get(username=receiver_username)
            CallHistory.objects.create(caller=caller, receiver=receiver)
            logger.info(f"CallHistory: {caller_username} → {receiver_username}")
        except User.DoesNotExist:
            logger.error("Failed to create CallHistory: user not found")

    async def receive(self, text_data):
        data = json.loads(text_data)
        msg_type = data.get('type')
        target_user = data.get('target')

        if msg_type == 'call' and target_user:
            if await self.user_exists(target_user):
                await self.set_user_busy(self.username, True, target_user)
                await self.set_user_busy(target_user, True, self.username)
                await self.create_call_history(self.username, target_user)

                logger.info(f"Call sent from {self.username} to {target_user}")
                try:
                    await self.channel_layer.group_send(
                        f"user_{target_user}",
                        {
                            'type': 'call',
                            'payload': {
                                'from': self.username,
                                'walletCoins': float(await self.get_wallet_balance(self.username) or 0)
                            }
                        }
                    )
                except Exception as e:
                    logger.error(f"Notify failed: {e}")
            else:
                logger.warning(f"Target user {target_user} does not exist")

        elif msg_type == 'end_call' and target_user:
            await self.set_user_busy(self.username, False)
            await self.set_user_busy(target_user, False)

            for user in [self.username, target_user]:
                try:
                    await self.channel_layer.group_send(
                        f"user_{user}",
                        {'type': 'call.ended'}
                    )
                except Exception as e:
                    logger.error(f"End call notify failed for {user}: {e}")

            logger.info(f"Call ended between {self.username} and {target_user}")

        elif msg_type == 'set_in_call':
            user = data.get('user')
            in_call_with = data.get('in_call_with')
            await self.set_user_busy(user, True, in_call_with)

        elif msg_type == 'endCall':
            user = data.get('user')
            await self.set_user_busy(user, False)

    async def call_ended(self, event):
        await self.send(text_data=json.dumps({'type': 'end_call'}))

    async def call(self, event):
        await self.send(text_data=json.dumps({
            'type': 'call',
            'payload': event.get('payload', {})
        }))

    async def send_json(self, event):
        await self.send(text_data=json.dumps(event['data']))


class OnlineUserConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        logger.info("User joined online_users group")
        try:
            await self.channel_layer.group_add("online_users", self.channel_name)
            await self.accept()
        except Exception as e:
            logger.error(f"Join online_users failed: {e}")
            await self.close()

    async def disconnect(self, close_code):
        logger.info("User left online_users group")
        try:
            await self.channel_layer.group_discard("online_users", self.channel_name)
        except Exception as e:
            logger.error(f"Leave online_users failed: {e}")

    async def receive(self, text_data):
        data = json.loads(text_data)
        if data.get("type") == "call_update":
            try:
                await self.channel_layer.group_send(
                    "online_users",
                    {
                        "type": "broadcast.call",
                        "payload": data.get("payload")
                    }
                )
                logger.info(f"Broadcasted call update")
            except Exception as e:
                logger.error(f"Broadcast call update failed: {e}")

    async def broadcast_call(self, event):
        await self.send(text_data=json.dumps({
            "type": "call",
            "payload": event.get("payload")
        }))


class HomeUserConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        logger.info("User joined home_users group")
        try:
            await self.channel_layer.group_add("home_users", self.channel_name)
            await self.accept()
        except Exception as e:
            logger.error(f"Join home_users failed: {e}")
            await self.close()

    async def disconnect(self, close_code):
        logger.info("User left home_users group")
        try:
            await self.channel_layer.group_discard("home_users", self.channel_name)
        except Exception as e:
            logger.error(f"Leave home_users failed: {e}")

    async def refresh_online_users(self, event):
        await self.send(text_data=json.dumps({
            "type": "refresh_users",
            "payload": {
                "users": event.get("online_users", [])
            }
        }))
