from django.urls import path
from . import views
#from .views import api_signup, api_login
from .views import api_signup, api_login
from .views import get_kyc_status  # ✅ Make sure this is here jkl
from .views import submit_kyc
from .views import request_withdrawal
from .views import confirm_payment
from .views import get_matched_user

from .views import transaction_list_view
from .views import user_ping

from .views import tax_summary_view

from .views import CallHistoryListView

from .views import WalletTransactionHistoryView

#from .views.agora import generate_agora_token
from .views import generate_agora_token
from .views import withdrawal_history


from .views import frontend_log_view


from .views import recent_calls




from .views import website_login


#from .views import health_check  # adjust import path if needed




urlpatterns = [
    
    #path("health/", health_check, name="health-check"),
    #path("health", health_check, name="health-check"),
    # Home
    path('api/home/', views.home_view, name='home'),
    # path('', views.home, name='home'),  # Duplicate home view (commented)

    # Authenticakjjkljtion
    #path('api/signup/', views.signup_view, name='signup'),
    #path('api/login/', views.login_view, name='login'),
    #path('api/logout/', views.custom_logout_view, name='logout'),

    # Duplicate API signup/login/logout (different views - keep commented)
    path('api/signup/', api_signup, name='api_signup'),
    path('api/login/', api_login, name='api_login'),
    path('api/logout/', api_login, name='api_logout'),

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
    path('api/toggle-online/', views.toggle_online, name='toggle_online'),
    # path('toggle-online/', views.toggle_online_status, name='toggle_online'),  # duplicate

    # Call Status Checking
    path('api/check-call-status/', views.check_call_status, name='check_call_status'),
    path('api/check-incoming-call/', views.check_incoming_call, name='check_incoming_call'),
    #path('api/accept-call/', views.accept_call, name='accept_call'),

    # Duplicate non-API call status checking (commented out)
    # path('check-call-status/', views.check_call_status, name='check_call_status'),
    # path('check_incoming_call/', views.check_incoming_call, name='check_incoming_call'),
    # path('accept-call/', views.accept_call, name='accept_call'),

    # Additional routes
    path('api/deduct-coins/', views.deduct_coins, name='deduct_coins'),  # No duplicate, keep
    #path('upload-kyc/', views.submit_kyc, name='submit_kyc'),
    #path('get-kyc-status/', get_kyc_status, name='get_kyc_status'),

    path('submit-kyc/', submit_kyc, name='submit_kyc'),            # For submitting KYC
    path('get-kyc-status/', get_kyc_status, name='get_kyc_status'),# For retrieving KYC status/details
    path('request-withdrawal/', request_withdrawal, name='request_withdrawal'),  # 💰 this one
    path('withdrawal-history/', withdrawal_history),

    path('api/get-matched-user/', get_matched_user, name='get-matched-user'),
    
    path('get-earnings-wallet/', views.get_earnings_wallet, name='get_earnings_wallet'),
    path('create-order/', views.create_order, name='create_order'),
    path('payment-success/', views.razorpay_payment_success),
    path('confirm-payment/', confirm_payment, name='confirm_payment'),
    path('api/website-logout/', views.website_logout, name='website_logout'), #for githjkhub website only
    path('api/website-login/', website_login, name='website-login'), #for github website only ok ok
    path('api/get-wallet-balance-public/', views.get_wallet_balance_public, name='get_wallet_balance_public'),
    path('api/wallet-history/', WalletTransactionHistoryView.as_view(), name='wallet-history'),
    path('api/call-history/', CallHistoryListView.as_view(), name='call-history'),
    path('api/agora/token/', generate_agora_token),
    path('api/agora-app-id/', views.get_agora_app_id),
    #path('log/frontend/', frontend_log_view, name='frontend-log'),  ok
    path('api/log/frontend/', frontend_log_view, name='frontend-log'),
    path('api/recent-calls/', recent_calls, name='recent-calls'),
    path('tax-access/<str:token>/', tax_summary_view, name='tax-summary'),
    path('transactions/', transaction_list_view, name='transaction_list_view'),
    path('api/ping/', user_ping),

]  
