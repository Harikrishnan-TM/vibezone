from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.contrib.auth.views import LoginView
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q, Count
from datetime import timedelta
import json

from .models import User, Wallet, Call
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework import status


# -------------------- AUTH --------------------

# API for signup
@api_view(['POST'])
@permission_classes([AllowAny])
def api_signup(request):
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
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


# API for login
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


# API for logout
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_logout(request):
    if request.user.is_authenticated:
        request.user.is_online = False
        request.user.incoming_call_from = ''
        request.user.in_call_with = None
        request.user.is_busy = False
        request.user.save()

    logout(request)
    return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)


# -------------------- MAIN VIEWS --------------------

# API for home screen (online users, wallet info)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def home(request):
    call = Call.objects.filter(
        Q(caller=request.user) | Q(receiver=request.user),
        active=True
    ).first()

    if call:
        return Response({'redirect': 'call'})

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
        'is_girl': girl.is_girl,
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


# API for online users
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def online_users(request):
    if request.user.in_call_with:
        active_call = Call.objects.filter(
            Q(caller=request.user) | Q(receiver=request.user),
            active=True
        ).first()
        if active_call:
            return Response({'redirect': 'call'})
        else:
            request.user.in_call_with = ''
            request.user.incoming_call_from = ''
            request.user.save()

    girls_online = User.objects.filter(
        is_online=True,
        is_girl=True
    ).exclude(id=request.user.id)

    girls_list = [{
        'username': girl.username,
        'is_girl': girl.is_girl,
    } for girl in girls_online]

    return Response({
        'online_users': girls_list,
        'me': {
            'username': request.user.username,
            'is_girl': request.user.is_girl
        }
    })



# -------------------- CALL LOGIC --------------------

# API for calling a user
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_call_user(request):
    target_username = request.data.get('target_username')
    target = get_object_or_404(User, username=target_username)

    if target.in_call_with or not target.is_online:
        return Response({'error': f"{target.username} is currently unavailable."}, status=status.HTTP_400_BAD_REQUEST)

    target.incoming_call_from = request.user.username
    target.in_call_with = request.user.username
    target.is_busy = True
    target.save()

    request.user.in_call_with = target.username
    request.user.is_busy = True
    request.user.save()

    return Response({'redirect': 'call'})


# API for handling the call view
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_call_view(request):
    user = request.user
    other_username = user.in_call_with

    if not other_username:
        return Response({'redirect': 'online_users'})

    other_user = User.objects.filter(username=other_username).first()
    if not other_user:
        return Response({'redirect': 'online_users'})

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


# API for accepting a call
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_accept_call(request):
    data = request.data
    target_username = data.get('target_username')
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


# API for ending a call
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_end_call(request):
    data = request.data
    target_username = data.get('target_username')
    user = request.user
    target = User.objects.filter(username=target_username).first()

    for u in filter(None, [user, target]):
        u.in_call_with = ''
        u.incoming_call_from = ''
        u.is_busy = False
        u.save()

    if target:
        call = Call.objects.filter(
            Q(caller=user, receiver=target) | Q(caller=target, receiver=user),
            active=True
        ).first()

        if call:
            call.active = False
            call.end_time = timezone.now()
            call.save()

    return Response({"success": True})


# -------------------- COINS --------------------

# API for deducting coins during a call
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_deduct_coins(request):
    user = request.user
    if user.in_call_with:
        if user.is_girl:
            user.wallet.add_coin(1)
        else:
            success = user.wallet.deduct_coin(1)
            if not success:
                return Response({'end_call': True})

    return Response({'success': True, 'coins': user.wallet.coins})


# API for buying coins
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_buy_coins(request):
    coins_to_add = int(request.data.get('coins', 0))
    if coins_to_add > 0:
        request.user.wallet.coins += coins_to_add
        request.user.wallet.save()
        return Response({'message': f'{coins_to_add} coins added to your wallet!', 'coins': request.user.wallet.coins})
    else:
        return Response({'error': 'Please enter a valid number of coins.'}, status=status.HTTP_400_BAD_REQUEST)


# API for getting the wallet balance
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_get_wallet_balance(request):
    return Response({'coins': request.user.wallet.coins})


# -------------------- UTILITIES --------------------

# API for toggling online status
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_toggle_online_status(request):
    if request.user.is_girl:
        request.user.is_online = not request.user.is_online
        request.user.save()

    return Response({'status': 'success'})


# API for checking if the user is in a call
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_check_call_status(request):
    call = Call.objects.filter(
        Q(caller=request.user) | Q(receiver=request.user),
        active=True
    ).first()
    return Response({'in_call': bool(call)})


# API for checking if the user is being called
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_check_incoming_call(request):
    if not request.user.is_girl:
        return Response({'being_called': False})

    incoming = Call.objects.filter(
        receiver=request.user,
        active=True,
        accepted=False
    ).exists()

    return Response({'being_called': incoming})


# -------------------- HELLO WORLD --------------------

# API endpoint to test the API
@api_view(['GET'])
@permission_classes([AllowAny])
def hello_world(request):
    return Response({"message": "Hello from Django API!"})