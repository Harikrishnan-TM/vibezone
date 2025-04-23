from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.contrib.auth.views import LoginView
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
from django.db.models import Q, Count
from datetime import timedelta
import json

from .models import User, Wallet, Call
from .forms import CustomUserCreationForm

from rest_framework.decorators import api_view
from rest_framework.response import Response

from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.permissions import IsAuthenticated



# -------------------- AUTH --------------------

#@api_view(['POST'])
#@permission_classes([AllowAny])
#def signup_view(request):
#   form = CustomUserCreationForm(request.data)
#    if form.is_valid():
#       user = form.save()
#        login(request, user)
#        user.is_online = not user.is_girl
#        user.save()
#        Wallet.objects.get_or_create(user=user)
#        token, _ = Token.objects.get_or_create(user=user)
#       return Response({
#            'message': 'Signup successful',
#            'token': token.key,
#           'username': user.username,
#            'is_girl': user.is_girl,
#            'coins': user.wallet.coins,
#        }, status=status.HTTP_201_CREATED)
#    return Response({'errors': form.errors}, status=status.HTTP_400_BAD_REQUEST)


#@api_view(['POST'])
#@permission_classes([AllowAny])
#def custom_login_view(request):
#    username = request.data.get('username')
#    password = request.data.get('password')

#    user = authenticate(username=username, password=password)
#    if user is None:
#        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

#    login(request, user)
#   user.is_online = not user.is_girl
#    user.save()

#    token, _ = Token.objects.get_or_create(user=user)
#    return Response({
#       'message': 'Login successful',
#       'token': token.key,
#        'username': user.username,
#        'is_girl': user.is_girl,
#        'coins': user.wallet.coins
#    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def custom_logout_view(request):
    user = request.user
    user.is_online = False
    user.incoming_call_from = ''
    user.in_call_with = None
    user.is_busy = False
    user.save()
    logout(request)
    return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)


# -------------------- MAIN VIEWS --------------------

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def home(request):
    # Check if user is already in a call
    call = Call.objects.filter(
        Q(caller=request.user) | Q(receiver=request.user),
        active=True
    ).first()

    if call:
        return Response({'redirect': 'call'})

    # Get girls online, not busy, and not the current user
    one_hour_ago = timezone.now() - timedelta(hours=1)
    girls = User.objects.filter(
        is_girl=True,
        is_online=True,
        is_busy=False,
    ).exclude(id=request.user.id).annotate(
        recent_calls=Count(
            'incoming_calls',
            filter=Q(incoming_calls__start_time__gte=one_hour_ago)
        )
    ).order_by('recent_calls', 'last_login')

    girls_list = [{
        'username': girl.username,
        'recent_calls': girl.recent_calls,
        'last_login': girl.last_login
    } for girl in girls]

    return Response({
        'wallet': request.user.wallet.coins,
        'user': {
            'username': request.user.username,
            'is_girl': request.user.is_girl,
        },
        'online_users': girls_list,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def online_users(request):
    # Check for active call
    if request.user.in_call_with:
        active_call = Call.objects.filter(
            Q(caller=request.user) | Q(receiver=request.user),
            active=True
        ).first()
        if active_call:
            return Response({'redirect': 'call'})
        else:
            # Clean up inconsistent call state
            request.user.in_call_with = ''
            request.user.incoming_call_from = ''
            request.user.save()

    girls_online = User.objects.filter(
        is_online=True,
        is_girl=True
    ).exclude(id=request.user.id)

    online_list = [{
        'username': girl.username,
        'is_girl': girl.is_girl,
    } for girl in girls_online]

    return Response({
        'online_users': online_list,
        'me': {
            'username': request.user.username,
            'is_girl': request.user.is_girl
        }
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def call_user(request, username):
    target = get_object_or_404(User, username=username)

    if target.in_call_with or not target.is_online:
        return Response({
            'error': f'{target.username} is currently unavailable.'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Update both users
    target.incoming_call_from = request.user.username
    target.in_call_with = request.user.username
    target.is_busy = True
    target.save()

    request.user.in_call_with = target.username
    request.user.is_busy = True
    request.user.save()

    return Response({
        'message': 'Call initiated.',
        'redirect': 'call'
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def call_view(request):
    user = request.user
    other_username = user.in_call_with

    if not other_username:
        return Response({'redirect': 'online_users'})

    other_user = User.objects.filter(username=other_username).first()
    if not other_user:
        return Response({'redirect': 'online_users'})

    # Find or create call
    call = Call.objects.filter(
        Q(caller=user, receiver=other_user) |
        Q(caller=other_user, receiver=user),
        active=True
    ).first()

    if not call:
        call = Call.objects.create(caller=user, receiver=other_user)
    elif not call.accepted and user.username != call.caller.username:
        call.accepted = True
        call.save()

    return Response({
        'app_id': settings.AGORA_APP_ID,
        'username': user.username,
        'other_user': other_user.username,
        'is_girl': user.is_girl,
        'is_initiator': user.username == call.caller.username
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def accept_call(request):
    target_username = request.data.get('target_username')
    user = request.user

    call = Call.objects.filter(
        caller__username=target_username,
        receiver=user,
        active=True,
        accepted=False
    ).first()

    if call:
        call.accepted = True
        call.save()

    return Response({'accepted': True})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def end_call(request):
    target_username = request.data.get('target_username')
    user = request.user
    target = User.objects.filter(username=target_username).first()

    # Reset status for both users
    for u in filter(None, [user, target]):
        u.in_call_with = ''
        u.incoming_call_from = ''
        u.is_busy = False
        u.save()

    # Mark call as inactive
    if target:
        call = Call.objects.filter(
            Q(caller=user, receiver=target) |
            Q(caller=target, receiver=user),
            active=True
        ).first()

        if call:
            call.active = False
            call.end_time = timezone.now()
            call.save()

    return Response({"success": True})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deduct_coins(request):
    user = request.user

    if user.in_call_with:
        if user.is_girl:
            user.wallet.add_coin(1)
        else:
            success = user.wallet.deduct_coin(1)
            if not success:
                return Response({'end_call': True, 'message': 'Insufficient coins'}, status=402)

    return Response({
        'success': True,
        'coins': user.wallet.coins
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def buy_coins(request):
    coins_to_add = request.data.get('coins')

    try:
        coins_to_add = int(coins_to_add)
    except (ValueError, TypeError):
        return Response({'error': 'Invalid number of coins'}, status=status.HTTP_400_BAD_REQUEST)

    if coins_to_add > 0:
        request.user.wallet.coins += coins_to_add
        request.user.wallet.save()
        return Response({
            'message': f'{coins_to_add} coins added to your wallet!',
            'coins': request.user.wallet.coins
        })
    else:
        return Response({'error': 'Please enter a valid number of coins.'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_wallet_balance(request):
    return Response({
        'coins': request.user.wallet.coins
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def toggle_online_status(request):
    user = request.user
    if user.is_girl:
        user.is_online = not user.is_online
        user.save()
    return Response({'is_online': user.is_online})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def profile_view(request):
    user = request.user
    return Response({
        'username': user.username,
        'email': user.email,
        'is_girl': user.is_girl,
        'is_online': user.is_online,
        'coins': user.wallet.coins if hasattr(user, 'wallet') else 0
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def online_users_partial(request):
    one_hour_ago = timezone.now() - timedelta(hours=1)

    girls = User.objects.filter(
        is_girl=True,
        is_online=True,
        is_busy=False
    ).exclude(id=request.user.id).annotate(
        recent_calls=Count(
            'incoming_calls',
            filter=Q(incoming_calls__start_time__gte=one_hour_ago)
        )
    ).order_by('recent_calls', 'last_login')

    online_users_data = [
        {
            'username': girl.username,
            'is_online': girl.is_online,
            'recent_calls': girl.recent_calls,
            'last_login': girl.last_login,
        }
        for girl in girls
    ]

    return Response({
        'online_users': online_users_data,
        'me': request.user.username,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_call_status(request):
    call = Call.objects.filter(
        Q(caller=request.user) | Q(receiver=request.user),
        active=True
    ).first()
    return Response({'in_call': bool(call)})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_incoming_call(request):
    if not request.user.is_girl:
        return Response({'being_called': False})

    incoming = Call.objects.filter(
        receiver=request.user,
        active=True,
        accepted=False
    ).exists()

    return Response({'being_called': incoming})


@api_view(['GET'])
def hello_world(request):
    return Response({"message": "Hello from Django API!"})





@api_view(['POST'])
@permission_classes([AllowAny])
def api_signup(request):
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
#    is_girl = request.data.get('is_girl') in ['true', 'True', True] small edit
     is_girl = str(request.data.get('is_girl')).lower() == 'true'


    if not all([username, email, password]):
        return Response({'error': 'All fields are required.'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already taken.'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(
        username=username,
        email=email,
        password=password,
        is_girl=is_girl,
        is_online=not is_girl,
    )

    Wallet.objects.create(user=user)
    token, _ = Token.objects.get_or_create(user=user)

    return Response({
        'token': token.key,
        'username': user.username,
        'is_girl': user.is_girl,
        'coins': user.wallet.coins
    }, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([AllowAny])
def api_login(request):
    username = request.data.get('username')
    password = request.data.get('password')

    user = authenticate(username=username, password=password)
    if user is None:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    user.is_online = not user.is_girl
    user.save()

    token, _ = Token.objects.get_or_create(user=user)

    return Response({
        'token': token.key,
        'username': user.username,
        'is_girl': user.is_girl,
        'coins': user.wallet.coins
    })