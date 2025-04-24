from django.urls import path
from . import views
from .views import api_signup, api_login

urlpatterns = [
    path('', views.home, name='home'),
    path('profile/', views.profile_view, name='profile'),
#    path('signup/', views.signup_view, name='signup'),
#    path('login/', views.CustomLoginView.as_view(), name='login'),
#    path('logout/', views.custom_logout_view, name='logout'),
    path('buy-coins/', views.buy_coins, name='buy_coins'),
    path('online/', views.online_users, name='online_users'),
    path('call/<str:username>/', views.call_user, name='call_user'),
    path('call/', views.call_view, name='call'),
    path('end-call/', views.end_call, name='end_call'),
    path('toggle-online/', views.toggle_online_status, name='toggle_online'),
    path('online/partial/', views.online_users_partial, name='online_users_partial'),
    path('deduct-coins/', views.deduct_coins, name='deduct_coins'),
    path('api/get-wallet-balance/', views.get_wallet_balance, name='get_wallet_balance'),
    path('check-call-status/', views.check_call_status, name='check_call_status'),
    path('check_incoming_call/', views.check_incoming_call, name='check_incoming_call'),
    path('accept-call/', views.accept_call, name='accept_call'),
    path('api/signup/', api_signup, name='api_signup'),
    path('api/login/', api_login, name='api_login'),

]
