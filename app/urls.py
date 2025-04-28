from django.urls import path
from . import views
#from .views import api_signup, api_login
from .views import signup_view, api_login

urlpatterns = [

    # Home
    path('api/home/', views.home_view, name='home'),
    # path('', views.home, name='home'),  # Duplicate home view (commented)

    # Authentication
    path('api/signup/', views.signup_view, name='signup'),
    path('api/login/', views.login_view, name='login'),
    path('api/logout/', views.custom_logout_view, name='logout'),

    # Duplicate API signup/login/logout (different views - keep commented)
    # path('api/signup/', api_signup, name='api_signup'),
    # path('api/login/', api_login, name='api_login'),
    # path('api/logout/', api_login, name='api_logout'),

    # User Profile and Wallet
    path('api/profile/', views.profile_view, name='profile'),
    path('api/buy-coins/', views.buy_coins, name='buy_coins'),
    path('api/get-wallet-balance/', views.get_wallet_balance, name='get_wallet_balance'),

    # Duplicate non-API versions (commented out)
    # path('profile/', views.profile_view, name='profile'),
    # path('buy-coins/', views.buy_coins, name='buy_coins'),

    # Online Users
    path('api/online-users/', views.online_users, name='online_users'),
    path('api/online-users-partial/', views.online_users_partial, name='online_users_partial'),

    # Duplicate non-API online users (commented out)
    # path('online/', views.online_users, name='online_users'),
    # path('online/partial/', views.online_users_partial, name='online_users_partial'),

    # Calling System
    path('api/call/<str:username>/', views.call_user, name='call_user'),
    path('api/call/', views.call_view, name='call'),  # receiving call
    path('api/end-call/', views.end_call, name='end_call'),

    # Duplicate non-API call system (commented out)
    # path('call/<str:username>/', views.call_user, name='call_user'),
    # path('call/', views.call_view, name='call'),
    # path('end-call/', views.end_call, name='end_call'),

    # Toggle Online/Offline
    path('api/toggle-online/', views.toggle_online_status, name='toggle_online'),
    # path('toggle-online/', views.toggle_online_status, name='toggle_online'),  # duplicate

    # Call Status Checking
    path('api/check-call-status/', views.check_call_status, name='check_call_status'),
    path('api/check-incoming-call/', views.check_incoming_call, name='check_incoming_call'),
    path('api/accept-call/', views.accept_call, name='accept_call'),

    # Duplicate non-API call status checking (commented out)
    # path('check-call-status/', views.check_call_status, name='check_call_status'),
    # path('check_incoming_call/', views.check_incoming_call, name='check_incoming_call'),
    # path('accept-call/', views.accept_call, name='accept_call'),

    # Additional routes
    path('deduct-coins/', views.deduct_coins, name='deduct_coins'),  # No duplicate, keep

]   
