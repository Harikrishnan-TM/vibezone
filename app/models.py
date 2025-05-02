from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

from django.contrib import admin

#from django.contrib.auth.models import User  # Import User model

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





class KYC(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    #user = models.ForeignKey(User, on_delete=models.CASCADE)  # Link KYC to a user
    name = models.CharField(max_length=255)
    bank_name = models.CharField(max_length=255)
    account_number = models.CharField(max_length=20)
    ifsc_code = models.CharField(max_length=11)
    #pan_card_image = models.ImageField(upload_to='kyc_pans/')  # Optional if not storing locally
    pan_card_image_url = models.URLField(blank=True, null=True)  # ✅ Add this
    kyc_status = models.CharField(default='Pending', max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name





class KYCAdmin(admin.ModelAdmin):
    list_display = ('name', 'bank_name', 'account_number', 'ifsc_code', 'kyc_status', 'created_at')
    list_filter = ('kyc_status',)  # Filter by status (pending, approved, rejected)
    search_fields = ('name', 'bank_name', 'account_number', 'ifsc_code')  # Allow searching by these fields

    # You can add this if you want the admin to be able to approve/reject directly
    actions = ['approve_kyc', 'reject_kyc']

    def approve_kyc(self, request, queryset):
        queryset.update(kyc_status='approved')
        self.message_user(request, "Selected KYC submissions have been approved.")

    def reject_kyc(self, request, queryset):
        queryset.update(kyc_status='rejected')
        self.message_user(request, "Selected KYC submissions have been rejected.")

admin.site.register(KYC, KYCAdmin)





