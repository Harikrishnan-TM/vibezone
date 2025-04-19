from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Wallet

class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'is_online', 'is_staff')
    search_fields = ('username', 'email')

admin.site.register(User, UserAdmin)
admin.site.register(Wallet)
