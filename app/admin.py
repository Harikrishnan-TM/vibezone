from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Wallet
from .models import User, Wallet, WithdrawalTransaction


from .models import CallHistory



class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'is_online', 'is_staff')
    search_fields = ('username', 'email')

@admin.register(WithdrawalTransaction)
class WithdrawalTransactionAdmin(admin.ModelAdmin):
    list_display = ('user', 'coins_requested', 'rupees_equivalent', 'status', 'created_at', 'processed_at')
    list_filter = ('status',)
    search_fields = ('user__username',)

admin.site.register(User, UserAdmin)
admin.site.register(Wallet)


@admin.register(CallHistory)
class CallHistoryAdmin(admin.ModelAdmin):
    list_display = ('caller', 'receiver', 'timestamp')
    search_fields = ('caller__username', 'receiver__username')