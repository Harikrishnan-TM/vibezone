from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.contrib import admin
from decimal import Decimal

# ======================
# ✅ Custom User Model jkl
# ======================

class User(AbstractUser):
    is_online = models.BooleanField(default=False)
    is_girl = models.BooleanField(default=False)
    is_busy = models.BooleanField(default=False)  # Tracks if user is currently in a call
    incoming_call_from = models.CharField(max_length=150, blank=True, null=True)
    last_seen = models.DateTimeField(null=True, blank=True)  # ⬅️ ADD THIS

    # ForeignKey to self for tracking who the user is currently in a call with some
    in_call_with = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='call_partner'
    )

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
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)  # Used for calls, purchases, etc.
    earnings_coins = models.IntegerField(default=0)  # Withdrawable by girls
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username}'s Wallet – ₹{self.balance}"

    def deduct_coin(self, amount=1):
        """Deduct a decimal amount from balance (used for calls)."""
        amount = Decimal(amount)
        if self.balance >= amount:
            self.balance -= amount
            self.save()
            return True
        return False

    def add_earnings(self, amount=1):
        """Add to earnings_coins (only used by girls for withdrawals)."""
        self.earnings_coins += int(amount)
        self.save()


# ======================
# 📞 Call Model
# ======================

class Call(models.Model):
    caller = models.ForeignKey(User, on_delete=models.CASCADE, related_name='outgoing_calls')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='incoming_calls')
    start_time = models.DateTimeField(default=timezone.now)
    end_time = models.DateTimeField(null=True, blank=True)
    active = models.BooleanField(default=True)
    accepted = models.BooleanField(default=False)

    def __str__(self):
        return f"Call between {self.caller.username} and {self.receiver.username} - {'Active' if self.active else 'Ended'}"

    @property
    def duration_seconds(self):
        """Return duration in seconds. If call is active, use current time."""
        end = self.end_time or timezone.now()
        return int((end - self.start_time).total_seconds())


# ======================
# 🧾 KYC Model & Admin
# ======================

class KYC(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=255)
    bank_name = models.CharField(max_length=255)
    account_number = models.CharField(max_length=20)
    ifsc_code = models.CharField(max_length=11)
    pan_card_image_url = models.URLField(blank=True, null=True)
    kyc_status = models.CharField(default='Pending', max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class KYCAdmin(admin.ModelAdmin):
    list_display = ('name', 'bank_name', 'account_number', 'ifsc_code', 'kyc_status', 'created_at')
    list_filter = ('kyc_status',)
    search_fields = ('name', 'bank_name', 'account_number', 'ifsc_code')
    actions = ['approve_kyc', 'reject_kyc']

    def approve_kyc(self, request, queryset):
        queryset.update(kyc_status='approved')
        self.message_user(request, "Selected KYC submissions have been approved.")

    def reject_kyc(self, request, queryset):
        queryset.update(kyc_status='rejected')
        self.message_user(request, "Selected KYC submissions have been rejected.")


admin.site.register(KYC, KYCAdmin)


# ======================
# 💸 Withdrawal Model
# ======================

class WithdrawalTransaction(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Transferred', 'Transferred'),
        ('Failed', 'Failed'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='withdrawal_transactions')
    coins_requested = models.IntegerField()
    rupees_equivalent = models.DecimalField(max_digits=10, decimal_places=2)  # e.g. 100 coins = ₹100
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    tds_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    def __str__(self):
        return f"{self.user.username} - {self.coins_requested} coins - ₹{self.rupees_equivalent} - {self.status}"


class WalletTransaction(models.Model):
    TRANSACTION_TYPE_CHOICES = [
        ('Recharge', 'Recharge'),
        ('Call', 'Call'),
        ('Admin_Adjustment', 'Admin_Adjustment'),  # Optional: keep only if you manually tweak balances
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='wallet_transactions')
    type = models.CharField(max_length=20, choices=TRANSACTION_TYPE_CHOICES)
    coins = models.IntegerField()  # Positive for additions, negative for deductions
    description = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} | {self.type} | {self.coins} | {self.description}"


# models.py
class CallHistory(models.Model):
    caller = models.ForeignKey(User, on_delete=models.CASCADE, related_name='calls_made')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='calls_received')
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.caller.username} → {self.receiver.username} @ {self.timestamp}"
