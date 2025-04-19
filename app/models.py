from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

# ======================
# ✅ Custom User Model
# ======================
class User(AbstractUser):
    is_online = models.BooleanField(default=False)
    is_girl = models.BooleanField(default=False)
    is_busy = models.BooleanField(default=False)  # ✅ NEW FIELD

    incoming_call_from = models.CharField(max_length=150, blank=True, null=True)
    in_call_with = models.CharField(max_length=150, blank=True, null=True)
    kyc_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.username

    def get_emoji_avatar(self):
        return "👩" if self.is_girl else "👨"


# ======================
# 💰 Wallet Model
# ======================
class Wallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='wallet')
    coins = models.IntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}'s Wallet – {self.coins} coins"

    def deduct_coin(self, amount=1):
        if self.coins >= amount:
            self.coins -= amount
            self.save()
            return True
        return False

    def add_coin(self, amount=1):
        self.coins += amount
        self.save()



# ======================
# 📞 Call Model
# ======================
# ======================
# 📞 Call Model
# ======================
class Call(models.Model):
    caller = models.ForeignKey(User, on_delete=models.CASCADE, related_name='outgoing_calls')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='incoming_calls')
    start_time = models.DateTimeField(default=timezone.now)
    end_time = models.DateTimeField(null=True, blank=True)
    active = models.BooleanField(default=True)
    accepted = models.BooleanField(default=False)  # ✅ NEW FIELD

    def __str__(self):
        return f"Call between {self.caller.username} and {self.receiver.username} - {'Active' if self.active else 'Ended'}"

    @property
    def duration_seconds(self):
        """Return duration in seconds. If call is active, use current time."""
        end = self.end_time or timezone.now()
        return int((end - self.start_time).total_seconds())

