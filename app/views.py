from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.contrib.auth.views import LoginView
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q, Count
from django.db.utils import OperationalError
from rest_framework.authtoken.models import Token
from django.http import JsonResponse



from decimal import Decimal
from .models import User, Wallet, Payment  # Make sure Payment is imported
import json




#from ratelimit.decorators import ratelimit
from django_ratelimit.decorators import ratelimit






from .models import Call, User























from .models import WithdrawalTransaction, User






from django.core.paginator import Paginator

from dateutil.relativedelta import relativedelta





from rest_framework import generics, permissions
from .models import CallHistory
from .serializers import CallHistorySerializer

import traceback

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication


from django.http import HttpResponseForbidden
from django.utils.timezone import now
from datetime import datetime
from .models import User, KYC, WithdrawalTransaction
import uuid






from django.db.models import Sum



































from app.models import Call, User  # adjust this if needed











import time


from agora_token_builder import RtcTokenBuilder



from rest_framework.views import APIView


from .models import WalletTransaction
from .serializers import WalletTransactionSerializer





from .models import WithdrawalTransaction





from django.contrib.auth.models import User



import redis


from django.db import OperationalError















from django.conf import settings






  # Adjust to your actual app name





from django.views.decorators.csrf import csrf_exempt






from app.models import Wallet



# views.py



from .models import User, Wallet  # Assuming you're using a custom user model




from django.contrib.auth import authenticate

from django.db.models import ObjectDoesNotExist






  # Adjust if your wallet model is elsewhere



import razorpay
import os

import logging

logger = logging.getLogger(__name__)  # Add this at the top of the file

# Importing the file upload utility
from .utils import upload_file_to_supabase

# Import your models
from app.models import User, Call, KYC, WithdrawalTransaction, Wallet  # Ensure these are correct

from .serializers import KYCSerializer
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status



# Python stdlib
from datetime import timedelta
import json

# Django REST framework
from rest_framework.permissions import AllowAny
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.contrib.auth import get_user_model

User = get_user_model()  # Make sure to use this if you're using the custom User model jk
from decimal import Decimal

from app.models import KYC  # Add only if not already included


# Your other views and logic...



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


#@api_view(['GET'])
#@permission_classes([IsAuthenticated])
#def check_call_status(request):
#    call = Call.objects.filter(
#        Q(caller=request.user) | Q(receiver=request.user),
#        active=True
#    ).first()
#    return Response({'in_call': bool(call)})


#@api_view(['GET'])
#@permission_classes([IsAuthenticated])
#def check_incoming_call(request):
#    if not request.user.is_girl:
#        return Response({'being_called': False})

#    incoming = Call.objects.filter(
#        receiver=request.user,
#        active=True,
#        accepted=False
#    ).exists()

#    return Response({'being_called': incoming})




#def health_check(request):
    #return JsonResponse({'status': 'ok'}, status=200)



@api_view(['GET'])
def hello_world(request):
    return Response({"message": "Hello from Django API!"})






@api_view(['GET'])
@permission_classes([IsAuthenticated])
def home_view(request):
    user = request.user

    # 1. Check if user is already in a call
    call = Call.objects.filter(
        Q(caller=user) | Q(receiver=user),
        active=True
    ).first()

    if call:
        return Response({'redirect': 'call'})

    # 2. Get list of online girls (not busy, not self)
    one_hour_ago = timezone.now() - timedelta(hours=1)
    girls = User.objects.filter(
        is_girl=True,
        is_online=True,
        is_busy=False,
    ).exclude(id=user.id).annotate(
        recent_calls=Count(
            'incoming_calls',
            filter=Q(incoming_calls__start_time__gte=one_hour_ago)
        )
    ).order_by('recent_calls', 'last_login')

    # 3. Format the online users list
    girls_list = []
    for girl in girls:
        girls_list.append({
            'username': girl.username,
            'recent_calls': girl.recent_calls,
            'last_login': girl.last_login.isoformat() if girl.last_login else None,
        })

    # 4. Return full home page info
    return Response({
        'wallet': user.wallet.balance,  # ✅ Updated from coins to balance
        'user': {
            'username': user.username,
            'is_girl': user.is_girl,
        },
        'online_users': girls_list,
    })















@api_view(['GET'])
@permission_classes([IsAuthenticated])
def online_users(request):
    user = request.user

    try:
        logger.info(f"[🧑‍💻] Online users endpoint hit by: {user.username}")

        # 1. Check for active call
        if user.in_call_with:
            active_call = Call.objects.filter(
                Q(caller=user) | Q(receiver=user),
                active=True
            ).first()

            if active_call:
                logger.info(f"[📞] Redirecting {user.username} to call screen.")
                return Response({'redirect': 'call'})
            else:
                logger.warning(f"[⚠️] {user.username} has inconsistent call state. Cleaning up.")
                user.in_call_with = None  # ✅ Updated from empty string to None
                user.incoming_call_from = ''
                user.is_busy = False
                user.save()

        # 2. Get list of online girls (excluding self)
        girls_online = User.objects.filter(
            is_online=True,
            is_girl=True
        )

        online_list = []
        for girl in girls_online:
            online_list.append({
                'username': girl.username,
                'is_girl': girl.is_girl,
            })

        logger.info(f"[✅] Returning {len(online_list)} online users to {user.username}.")

        return Response({
            'me': {
                'username': user.username,
                'is_girl': user.is_girl,
                'wallet': user.wallet.balance,  # ✅ Updated from coins to balance
            },
            'online_users': online_list,
        })

    except Exception as e:
        logger.error(f"[❌] Error in online_users: {str(e)}", exc_info=True)
        return Response({'error': 'Server error'}, status=500)







@api_view(['POST'])
@permission_classes([IsAuthenticated])
def call_user(request, username):
    target = get_object_or_404(User, username=username)

    if target.in_call_with or not target.is_online:
        return Response({
            'error': f'{target.username} is currently unavailable.'
        }, status=status.HTTP_400_BAD_REQUEST)

    # ✅ Update target user ok ok
    target.incoming_call_from = request.user.username
    target.in_call_with = request.user  # assigning User instance
    target.is_busy = True
    target.save()

    # ✅ Update caller user
    request.user.in_call_with = target
    request.user.is_busy = True
    request.user.save()

    # ✅ Save call history o ok ok ok ok ok
    #from .models import CallHistory  # just in case
    CallHistory.objects.create(caller=request.user, receiver=target)

    return Response({
        'message': 'Call initiated successfully.',
        'other_user': target.username,
        'wallet_balance': request.user.wallet.balance if hasattr(request.user, 'wallet') else 0,
        'is_initiator': True,
        'redirect': '/call'
    })








@api_view(['POST'])
@permission_classes([IsAuthenticated])
def call_view(request):
    target_username = request.data.get('target_username')
    user = request.user

    if not target_username:
        return Response({'error': 'Target username is required.'}, status=400)

    call = Call.objects.filter(
        caller__username=target_username,
        receiver=user,
        active=True,
        accepted=False
    ).first()

    if not call:
        return Response({'error': 'No pending call found.'}, status=404)

    # ✅ Accept the call
    call.accepted = True
    call.save()

    return Response({
        'message': 'Call accepted successfully.',
        'redirect': 'call'
    }, status=200)










@api_view(['POST'])
@permission_classes([IsAuthenticated])
def end_call(request):
    target_username = request.data.get('target_username')
    user = request.user

    if not target_username:
        return Response({'success': False, 'message': 'target_username is required.'}, status=400)

    target = User.objects.filter(username=target_username).first()

    if not target:
        return Response({'success': False, 'message': f'User \"{target_username}\" not found.'}, status=400)

    # 🔵 Reset statuses for both users (caller and receiver)
    for u in [user, target]:
        u.in_call_with = None
        u.incoming_call_from = ''
        u.is_busy = False
        u.save()

    # 🟣 Find the ongoing call and mark inactive
    call = Call.objects.filter(
        Q(caller=user, receiver=target) | Q(caller=target, receiver=user),
        active=True
    ).first()

    if call:
        call.active = False
        call.end_time = timezone.now()
        call.save()

    # 📡 Send 'end_call' message to both users over WebSocket
    channel_layer = get_channel_layer()
    for u in [user, target]:
        async_to_sync(channel_layer.group_send)(
            f"user_{u.username}",
            {
                "type": "send.json",
                "data": {
                    "type": "end_call",
                    "message": f"Call ended by {user.username}"
                }
            }
        )

    print(f"[END CALL] {user.username} ended call with {target.username}")

    return Response({"success": True})









@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deduct_coins(request):
    user = request.user
    callee = user.in_call_with  # the person the user is on a call with

    if callee:  # User is in a call
        if user.is_girl:
            user.wallet.add_earnings(1)
        else:
            success = user.wallet.deduct_coin(10)
            if not success:
                return Response({
                    'success': False,
                    'end_call': True,
                    'message': 'Insufficient coins',
                    'coins': float(user.wallet.balance),
                }, status=402)

            if callee.is_girl:
                callee.wallet.add_earnings(1)

    return Response({
        'success': True,
        'end_call': False,  # ✅ Always include this
        'coins': float(user.wallet.balance),
        'is_girl': user.is_girl  # ✅ add this line
    })











@api_view(['GET'])
@permission_classes([IsAuthenticated])
def profile_view(request):
    user = request.user

    # Try to fetch the latest KYC record for this user
    kyc_status = 'pending'
    try:
        kyc = KYC.objects.get(user=user)
        kyc_status = kyc.kyc_status
    except KYC.DoesNotExist:
        kyc_status = 'pending'

    return Response({
        'success': True,
        'data': {
            'username': user.username,
            'email': user.email,
            'is_girl': user.is_girl,
            'is_online': user.is_online,
            'earnings': user.wallet.earnings_coins if user.is_girl and hasattr(user, 'wallet') else None,
            'kyc_status': kyc_status,  # ✅ Added
            'in_call_with': user.in_call_with.username if user.in_call_with else None,  # ✅ Display who the user is in call with
        }
    })







@api_view(['POST'])
@permission_classes([IsAuthenticated])
def toggle_online(request):
    user = request.user

    if user.is_girl:
        user.is_online = not user.is_online
        user.save()

        # 🔄 Emit updated list of online users to all connected clients
        channel_layer = get_channel_layer()
        online_users = User.objects.filter(is_online=True).values('username')

        async_to_sync(channel_layer.group_send)(
            "home_users",  # Group name — must match in consumer
            {
                "type": "refresh.online.users",  # Must match a method like 'refresh_online_users' in the consumer
                "online_users": list(online_users)
            }
        )

    return Response({
        'success': True,
        'data': {
            'is_online': user.is_online,
            'in_call_with': user.in_call_with.username if user.in_call_with else None,  # ✅ Added the user's current call info
        }
    })







@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_wallet_balance(request):
    user = request.user
    wallet = getattr(user, 'wallet', None)

    return Response({
        'success': True,
        'data': {
            'balance': float(wallet.balance) if wallet else 0.0,  # Return ₹ balance
            'earnings_coins': wallet.earnings_coins if wallet else 0,  # Include earnings if needed
            'is_in_call': user.in_call_with.username if user.in_call_with else None
        }
    })



#only for website wallet balance



@api_view(['GET'])
def get_wallet_balance_public(request):
    username = request.GET.get('username')

    if not username:
        return Response({'success': False, 'error': 'Username is required'}, status=400)

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return Response({'success': False, 'error': 'User not found'}, status=404)

    wallet = getattr(user, 'wallet', None)

    return Response({
        'success': True,
        'data': {
            'balance': float(wallet.balance) if wallet else 0.0,
            'earnings_coins': wallet.earnings_coins if wallet else 0,
            'is_in_call': user.in_call_with.username if user.in_call_with else None
        }
    })



#only for website wallet balance








@api_view(['POST'])
@permission_classes([IsAuthenticated])
def buy_coins(request):
    raw_amount = request.data.get('amount')
    try:
        amount = int(raw_amount)
        if amount > 500:
            # ✅ Razorpay sends paise, convert to rupees
            amount = amount // 100
    except (ValueError, TypeError):
        return Response({'error': 'Invalid amount.'}, status=status.HTTP_400_BAD_REQUEST)

    coin_map = {100: 150, 200: 400, 300: 630, 400: 840}
    coins_to_add = coin_map.get(amount)

    if coins_to_add is None:
        return Response({'error': 'Invalid amount.'}, status=status.HTTP_400_BAD_REQUEST)

    wallet = getattr(request.user, 'wallet', None)
    if not wallet:
        return Response({'error': 'Wallet not found.'}, status=status.HTTP_400_BAD_REQUEST)

    wallet.balance += Decimal(coins_to_add)
    wallet.save()

    return Response({
        'message': f'{coins_to_add} coins added for ₹{amount}',
        'balance': float(wallet.balance)
    }, status=status.HTTP_200_OK)

   






@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_incoming_call(request):
    """
    Checks if the current user (who must be a 'girl') is receiving a call.
    Returns 'being_called': True or False.
    """
    user = request.user

    if not user.is_girl:
        return Response({'being_called': False})

    # ✅ Check if there's an active, unaccepted call where this user is the receiver
    incoming = Call.objects.filter(
        receiver=user,
        active=True,
        accepted=False
    ).exists()

    return Response({'being_called': incoming})







@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_call_status(request):
    """
    Check if the user is currently in an active call (either as caller or receiver).
    Returns 'in_call': True or False.
    """
    user = request.user

    try:
        call = Call.objects.filter(
            Q(caller=user) | Q(receiver=user),
            active=True
        ).first()

        return Response({'in_call': bool(call)})

    except Exception as e:
        return Response({'error': str(e)}, status=500)






@ratelimit(key='ip', rate='5/m', block=True)  # Limit: 5 signup attempts per IP per minute
@csrf_exempt
def api_signup(request):
    if request.method == 'POST':
        try:
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')
            is_girl = request.POST.get('is_girl') == 'true'

            if not all([username, email, password]):
                return JsonResponse({'message': 'All fields are required.'}, status=400)

            if User.objects.filter(username=username).exists():
                return JsonResponse({'message': 'Username already exists.'}, status=400)

            user = User.objects.create_user(username=username, email=email, password=password)
            user.is_girl = is_girl  # ✅ This line is assumed valid if you extended the User model
            user.save()

            token, _ = Token.objects.get_or_create(user=user)
            return JsonResponse({
                'token': token.key,
                'username': user.username  # ✅ Include username in the response
            }, status=201)

        except OperationalError:
            return JsonResponse({'message': 'Database error. Please try again later.'}, status=500)
        except Exception as e:
            return JsonResponse({'message': f'Unexpected error: {str(e)}'}, status=500)

    return JsonResponse({'message': 'Invalid request method.'}, status=405)




#def check_redis_connection():
#    try:
#        r = redis.Redis.from_url("redis://default:AXDNAAIjcDEwZGVjOGQ1MmI5M2Y0OGU2YmQzOThkYzRmNjA3OTMyYnAxMA@grateful-coyote-28877.upstash.io:6379")
#        r.ping()
#        logger.info("✅ Redis is connected and reachable.")
#    except Exception as e:
#        logger.error("❌ Redis connection failed: %s", str(e), exc_info=True)

#@csrf_exempt
#def api_signup(request):
#    if request.method != 'POST':
#        return JsonResponse({'message': 'Invalid request method.'}, status=405)

#    logger.info("📨 Signup POST request received.")

#    try:
#        check_redis_connection()

#        username = request.POST.get('username')
#        email = request.POST.get('email')
#        password = request.POST.get('password')
#        is_girl = request.POST.get('is_girl') == 'true'

#        logger.info(f"📝 Received signup data: username={username}, email={email}, is_girl={is_girl}")

#        if not all([username, email, password]):
#            logger.warning("❗ Missing required fields in signup form.")
#            return JsonResponse({'message': 'All fields are required.'}, status=400)

#        if User.objects.filter(username=username).exists():
#            logger.warning("❗ Username already exists: %s", username)
#            return JsonResponse({'message': 'Username already exists.'}, status=400)

#        user = User.objects.create_user(username=username, email=email, password=password)
#        user.is_girl = is_girl
#        user.save()

#        token, _ = Token.objects.get_or_create(user=user)

#        logger.info("✅ Signup successful for user: %s", username)
#        return JsonResponse({'token': token.key, 'username': user.username}, status=201)

#    except OperationalError as e:
#        logger.error("❌ Database OperationalError: %s", str(e), exc_info=True)
#        return JsonResponse({'message': 'Database error. Please try again later.'}, status=500)
#    except Exception as e:
#        logger.error("❌ Unexpected error in signup: %s", str(e), exc_info=True)
#        return JsonResponse({'message': f'Unexpected error: {str(e)}'}, status=500)




@ratelimit(key='ip', rate='10/m', block=True)  # ✅ Adjust rate as needed (e.g., 10 per minute)
@api_view(['POST'])
@permission_classes([AllowAny])
def api_login(request):
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({'error': 'Username and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

    #user = authenticate(username=username, password=password)
    user = authenticate(request=request, username=username, password=password)
    if user is None:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    user.is_online = not user.is_girl
    user.save()

    token, _ = Token.objects.get_or_create(user=user)

    wallet = getattr(user, 'wallet', None)
    coins = float(getattr(wallet, 'balance', 0)) if wallet else 0

    return Response({
        'token': token.key,
        'username': user.username,
        'is_girl': user.is_girl,
        'coins': coins
    })



#login view only for the github website ok ok ok ok ok ok ok


@api_view(['POST'])
def website_login(request):
    username = request.data.get('username')
    password = request.data.get('password')

    #user = authenticate(username=username, password=password)
    user = authenticate(request, username=username, password=password)  # ✅ Fix is here

    if user is not None:
        token, _ = Token.objects.get_or_create(user=user)
        user.is_online = True
        user.save()

        return Response({
            'token': token.key,
            'username': user.username,
            # 'is_girl': getattr(user.profile, 'is_girl', False)  # ← REMOVE THIS
        })
    else:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)




#login view only for the github website




@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_logout(request):
    user = request.user
    user.is_online = False
    user.incoming_call_from = ''
    user.in_call_with = None
    user.is_busy = False
    user.save()
    
    logout(request)  # For session-based logouts, if needed
    
    return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)



#view only for website front end on github


@api_view(['POST'])
def website_logout(request):
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Token '):
        return Response({'message': 'Authorization token missing'}, status=status.HTTP_400_BAD_REQUEST)

    token_key = auth_header.split(' ')[1]

    try:
        token = Token.objects.get(key=token_key)
        user = token.user
        user.is_online = False
        user.incoming_call_from = ''
        user.in_call_with = None
        user.is_busy = False
        user.save()
        token.delete()  # Optional: invalidate token immediately
        return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)
    except Token.DoesNotExist:
        return Response({'message': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

#view only for website front end on github

# views.py






@api_view(['POST'])
@permission_classes([IsAuthenticated])
def submit_kyc(request):
    if KYC.objects.filter(user=request.user).exists():
        return Response({
            'success': False,
            'message': 'KYC already submitted for this user.'
        }, status=status.HTTP_400_BAD_REQUEST)

    serializer = KYCSerializer(data=request.data)
    
    if serializer.is_valid():
        kyc = serializer.save(user=request.user)

        pan_card_image = request.FILES.get('pan_card_image')
        if pan_card_image:
            try:
                file_url = upload_file_to_supabase(pan_card_image, request.user.id)
                kyc.pan_card_image_url = file_url
                kyc.save()
            except Exception as e:
                return Response({
                    'success': False,
                    'message': f'File upload failed: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'success': True, 'message': 'KYC submitted successfully'}, status=status.HTTP_201_CREATED)

    return Response({
        'success': False,
        'message': 'Validation failed',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)








   






@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_kyc_status(request):
    try:
        kyc = KYC.objects.get(user=request.user)
        return Response({
            'name': kyc.name,
            'bank_name': kyc.bank_name,
            'account_number': kyc.account_number,
            'ifsc_code': kyc.ifsc_code,
            'pan_card_image_url': kyc.pan_card_image_url,
            'kyc_status': kyc.kyc_status,
        })
    except KYC.DoesNotExist:
        # Always return a valid kyc_status field for frontend compatibility
        return Response({
            'kyc_status': 'pending',
            'message': 'KYC not found for this user.'
        }, status=200)
    except Exception as e:
        return Response({'message': f'An error occurred: {str(e)}'}, status=500)








@api_view(['POST'])
@permission_classes([IsAuthenticated])
def request_withdrawal(request):
    user = request.user
    coins_requested = int(request.data.get('coins', 0))

    if coins_requested <= 0:
        return Response({'error': 'Invalid coin amount.'}, status=status.HTTP_400_BAD_REQUEST)

    wallet = user.wallet

    # Check if user has enough earnings coins (not balance)
    if wallet.earnings_coins < coins_requested:
        return Response({'error': 'Not enough earnings coins for withdrawal.'}, status=status.HTTP_400_BAD_REQUEST)

    # Check for existing pending withdrawal
    existing_withdrawal = WithdrawalTransaction.objects.filter(user=user, status='Pending').exists()
    if existing_withdrawal:
        return Response({'error': 'You have an existing pending withdrawal request.'}, status=status.HTTP_400_BAD_REQUEST)

    # Calculate rupee equivalent (assuming 1 coin = ₹1, adjust if needed) ok
    #rupees_equivalent = coins_requested * 1.0
    #rupees_equivalent = coins_requested * 0.5

    # Calculate rupee equivalent (1 coin = ₹0.25, 4 coins = ₹1)
    rupees_equivalent = coins_requested * 0.25


    # Deduct from earnings_coins
    wallet.earnings_coins -= coins_requested
    wallet.save()

    # Create withdrawal transaction
    WithdrawalTransaction.objects.create(
        user=user,
        coins_requested=coins_requested,
        rupees_equivalent=rupees_equivalent,
        status='Pending',
    )

    return Response({'success': True, 'message': 'Withdrawal request submitted successfully.'}, status=status.HTTP_201_CREATED)










@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_earnings_wallet(request):
    """
    Get the earnings wallet balance for girls (withdrawable coins).
    Assumes 'earnings_coins' field is separate from spendable balance.
    """
    user = request.user

    # ✅ Check if the user is a girl (performer)
    if not user.is_girl:
        return Response({'success': False, 'error': 'Access denied. Not a performer account.'}, status=403)

    wallet = getattr(user, 'wallet', None)
    earnings = wallet.earnings_coins if wallet else 0

    return Response({
        'success': True,
        'data': {
            'earnings_coins': earnings
        }
    })






@csrf_exempt
def create_order(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            amount = data.get('amount')

            if not amount or not isinstance(amount, int):
                return JsonResponse({"error": "Invalid amount"}, status=400)

            key_id = os.getenv("RAZORPAY_KEY_ID")
            key_secret = os.getenv("RAZORPAY_KEY_SECRET")

            if not key_id or not key_secret:
                return JsonResponse({"error": "Razorpay credentials not configured"}, status=500)

            client = razorpay.Client(auth=(key_id, key_secret))

            payment = client.order.create({
                "amount": amount * 100,  # Razorpay uses paise
                "currency": "INR",
                "payment_capture": "1"
            })

            # Return both order info and key to frontend
            return JsonResponse({
                "id": payment.get("id"),
                "amount": payment.get("amount"),
                "currency": payment.get("currency"),
                "key": key_id  # 🔑 include the Razorpay public key kjl
            })

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Only POST method allowed"}, status=405)







#@csrf_exempt
#def razorpay_payment_success(request):
    #if request.method != 'POST':
        #return JsonResponse({'error': 'Invalid request method'}, status=405)

    #try:
        #data = json.loads(request.body)
    #except json.JSONDecodeError:
        #return JsonResponse({'error': 'Invalid JSON'}, status=400)

    #payment_id = data.get('payment_id')
    #order_id = data.get('order_id')
    #signature = data.get('signature')
    #amount = data.get('amount')
    #user_id = data.get('user_id')

    #if not all([payment_id, order_id, signature, amount, user_id]):
        #return JsonResponse({'error': 'Missing required fields'}, status=400)

    #try:
        #user = User.objects.get(id=user_id)
    #except User.DoesNotExist:
        #return JsonResponse({'error': 'User not found'}, status=404)

    # 🔐 Check for duplicate payment
    #if Payment.objects.filter(payment_id=payment_id).exists():
        #return JsonResponse({'message': 'Payment already processed'}, status=200)

    # ✅ Verify Razorpay signature
    #client = razorpay.Client(auth=(os.getenv("RAZORPAY_KEY_ID"), os.getenv("RAZORPAY_KEY_SECRET")))
    #try:
        #client.utility.verify_payment_signature({
            #"razorpay_order_id": order_id,
            #"razorpay_payment_id": payment_id,
            #"razorpay_signature": signature
        #})
    #except razorpay.errors.SignatureVerificationError:
        #return JsonResponse({'error': 'Invalid payment signature'}, status=400)

    # 💰 Credit balance
    #coins = Decimal(str(amount))
    #wallet, _ = Wallet.objects.get_or_create(user=user)
    #wallet.balance += coins
    #wallet.save()

    # 🧾 Save payment
    #Payment.objects.create(
        #payment_id=payment_id,
        #order_id=order_id,
        #amount=coins,
        #user=user
    #)

    #return JsonResponse({'message': 'Coins added successfully', 'balance': str(wallet.balance)})


@csrf_exempt
def razorpay_payment_success(request):
    return JsonResponse({"status": "deprecated", "message": "Use /confirm-payment/ instead."})













#control coins to be credited in this view
@csrf_exempt
def confirm_payment(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    # Extract required fields
    payment_id = data.get("payment_id")
    order_id = data.get("order_id")
    signature = data.get("signature")
    amount = data.get("amount")  # Razorpay amount in paise
    username = data.get("username")

    if not all([payment_id, order_id, signature, amount, username]):
        return JsonResponse({"error": "Missing required fields"}, status=400)

    # Convert amount from paise to rupees
    try:
        amount_in_rs = int(amount) // 100  # Razorpay sends paise
    except ValueError:
        return JsonResponse({"error": "Invalid amount value"}, status=400)

    # Get user by username
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)

    # Verify Razorpay signature
    client = razorpay.Client(
        auth=(os.getenv("RAZORPAY_KEY_ID"), os.getenv("RAZORPAY_KEY_SECRET"))
    )
    try:
        client.utility.verify_payment_signature({
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": signature
        })
    except razorpay.errors.SignatureVerificationError:
        return JsonResponse({"error": "Payment signature invalid"}, status=400)

    # Coins mapping (₹ → coins)
    coin_map = {
        100: 150,
        200: 400,
        300: 630,
        400: 840,
    }

    coins_to_credit = Decimal(coin_map.get(amount_in_rs, amount_in_rs))  # fallback to amount_in_rs if not found

    # Update wallet
    wallet, _ = Wallet.objects.get_or_create(user=user)
    wallet.balance += coins_to_credit
    wallet.save()

    # Record payment (avoid duplicates)
    if not Payment.objects.filter(payment_id=payment_id).exists():
        Payment.objects.create(
            payment_id=payment_id,
            order_id=order_id,
            amount=coins_to_credit,
            user=user
        )

    return JsonResponse({
        "message": f"{coins_to_credit} coins added successfully",
        "balance": str(wallet.balance),
    })
#control coins to be credited in this view









@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_matched_user(request):
    user = request.user

    # The username of the user currently calling this user
    caller_username = user.incoming_call_from

    if caller_username:
        return Response({'username': caller_username})
    else:
        # No incoming call found
        return Response({'username': None})





@api_view(['GET'])
@permission_classes([IsAuthenticated])
def withdrawal_history(request):
    withdrawals = WithdrawalTransaction.objects.filter(user=request.user).order_by('-created_at')
    data = [
        {
            'coins_requested': w.coins_requested,
            'rupees_equivalent': str(w.rupees_equivalent),
            'status': w.status,
            'created_at': w.created_at,
            'processed_at': w.processed_at,
        }
        for w in withdrawals
    ]
    return Response({'history': data})






logger = logging.getLogger(__name__)

class WalletTransactionHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        logger.info(f"📤 Fetching wallet transactions for user: {user.username}")

        transactions = WalletTransaction.objects.filter(user=user).order_by('-created_at')
        logger.info(f"💰 Found {transactions.count()} transactions for {user.username}")

        serializer = WalletTransactionSerializer(transactions, many=True)
        return Response(serializer.data)









# Initialize logger
logger = logging.getLogger(__name__)

class CallHistoryListView(generics.ListAPIView):
    """
    API view to list all call history entries for the authenticated user.
    """
    serializer_class = CallHistorySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        logger.info(f"[📞] Fetching call history for user: {user.username}")

        queryset = CallHistory.objects.filter(
            Q(caller=user) | Q(receiver=user)
        ).distinct().order_by('-timestamp')

        logger.info(f"[🧾] Found {queryset.count()} call history records for {user.username}")
        return queryset




# views/agora.py



APP_ID = os.getenv("AGORA_APP_ID")
APP_CERTIFICATE = os.getenv("AGORA_APP_CERTIFICATE")
TOKEN_EXPIRATION_SECONDS = 3600  # Token valid for 1 hour ok



@csrf_exempt
def generate_agora_token(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Only GET method is allowed'}, status=405)

    channel_name = request.GET.get('channel_name')
    uid = request.GET.get('uid', '0')

    if not channel_name:
        return JsonResponse({'error': 'Missing channel_name parameter'}, status=400)

    try:
        uid_int = int(uid)
    except ValueError:
        return JsonResponse({'error': 'UID must be an integer'}, status=400)

    if not APP_ID or not APP_CERTIFICATE:
        return JsonResponse({'error': 'Agora credentials not configured'}, status=500)

    current_time = int(time.time())
    expiration_time = current_time + TOKEN_EXPIRATION_SECONDS

    try:
        print("🟢 Agora Token Generation started")
        print("App ID:", APP_ID)
        print("Channel Name:", channel_name)
        print("UID:", uid_int)
        print("Expiration:", expiration_time)

        token = RtcTokenBuilder.buildTokenWithUid(
            appId=APP_ID,
            appCertificate=APP_CERTIFICATE,
            channelName=channel_name,
            uid=uid_int,
            #role=RtcTokenBuilder.Role_Attendee,
            role = 1,  # Attendee role
            privilegeExpiredTs=expiration_time,
        )
    except Exception as e:
        print("🔴 Token generation error:", str(e))
        traceback.print_exc()  # ← this is what will show the real cause in logs
        return JsonResponse({'error': f'Token generation failed: {str(e)}'}, status=500)

    return JsonResponse({
        'token': token,
        'uid': uid_int,
        'channel': channel_name,
        'expires_in': TOKEN_EXPIRATION_SECONDS
    })





@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_agora_app_id(request):
    return Response({'agora_app_id': APP_ID})




# Django view
@api_view(["POST"])
@authentication_classes([TokenAuthentication])
def frontend_log_view(request):
    message = request.data.get("message")
    level = request.data.get("level", "info")
    print(f"[FlutterLog][{level.upper()}] {message}")
    return Response({"status": "logged"})





@api_view(["GET"])
def recent_calls(request):
    user = request.user

    # Filter calls where user was either the caller or receiver ok ok ok ok
    calls = CallHistory.objects.filter(
        Q(caller=user) | Q(receiver=user)
    ).order_by("-timestamp")[:10]

    # Get the other participant in each call
    recent_contacts = []
    seen_users = set()

    for call in calls:
        other_user = call.receiver if call.caller == user else call.caller
        if other_user.username not in seen_users:
            seen_users.add(other_user.username)
            recent_contacts.append({
                "username": other_user.username,
                "user_id": other_user.id
            })

    return Response(recent_contacts)





def tax_summary_view(request, token):
    """
    Comprehensive TDS Summary Report for CA - Form 26Q Compliance
    Shows all users with withdrawals, TDS calculations, and quarter-wise filtering
    """
    if token != settings.SECRET_TAX_TOKEN:
        return HttpResponseForbidden("Unauthorized access.")

    # Get selected financial year (default to current FY)
    try:
        selected_year = int(request.GET.get('year', ''))
    except (ValueError, TypeError):
        current_date = datetime.now()
        selected_year = current_date.year if current_date.month >= 4 else current_date.year - 1

    # Financial year boundaries (April 1 to March 31)
    start_of_fy = datetime(selected_year, 4, 1)
    end_of_fy = datetime(selected_year + 1, 3, 31, 23, 59, 59)

    # Quarter filtering
    quarter = request.GET.get('quarter', '')
    if quarter:
        quarter_dates = {
            'Q1': (datetime(selected_year, 4, 1), datetime(selected_year, 6, 30, 23, 59, 59)),
            'Q2': (datetime(selected_year, 7, 1), datetime(selected_year, 9, 30, 23, 59, 59)),
            'Q3': (datetime(selected_year, 10, 1), datetime(selected_year, 12, 31, 23, 59, 59)),
            'Q4': (datetime(selected_year + 1, 1, 1), datetime(selected_year + 1, 3, 31, 23, 59, 59)),
        }
        if quarter in quarter_dates:
            start_of_fy, end_of_fy = quarter_dates[quarter]

    # Search/filter params
    search_query = request.GET.get('search', '').strip().lower()
    above_30000 = request.GET.get('above_30000') == '1'
    kyc_status_filter = request.GET.get('kyc_status', '').strip()

    # Get all users who have made withdrawals
    users = User.objects.filter(
        withdrawal_transactions__status='Transferred',
        withdrawal_transactions__created_at__gte=start_of_fy,
        withdrawal_transactions__created_at__lte=end_of_fy
    ).distinct()

    user_data = []
    total_gross = 0
    total_tds = 0
    count_above_30000 = 0
    count_below_30000 = 0

    for user in users:
        # Get KYC details
        kyc = KYC.objects.filter(user=user).first()
        
        # Calculate total withdrawn (gross amount)
        withdrawals = WithdrawalTransaction.objects.filter(
            user=user,
            status='Transferred',
            created_at__gte=start_of_fy,
            created_at__lte=end_of_fy
        )
        
        total_withdrawn = withdrawals.aggregate(total=Sum('rupees_equivalent'))['total'] or 0.0
        transaction_count = withdrawals.count()
        
        # TDS Calculation (10% for amounts > 30,000 under Section 194J)
        tds_amount = (total_withdrawn * 0.10) if total_withdrawn >= 30000 else 0.0
        net_payable = total_withdrawn - tds_amount
        
        data = {
            "username": user.username,
            "kyc_name": kyc.name if kyc else None,
            "pan_number": kyc.pan_number if kyc else None,
            "mobile_number": kyc.mobile_number if kyc else None,
            "kyc_status": kyc.kyc_status if kyc else "pending",
            "total_withdrawn": round(total_withdrawn, 2),
            "total_tds": round(tds_amount, 2),
            "net_payable": round(net_payable, 2),
            "transaction_count": transaction_count
        }
        
        # Apply search filter
        if search_query:
            searchable = f"{data['username']} {data['kyc_name'] or ''} {data['pan_number'] or ''} {data['mobile_number'] or ''}".lower()
            if search_query not in searchable:
                continue
        
        # Apply threshold filter
        if above_30000 and data["total_withdrawn"] < 30000:
            continue
            
        # Apply KYC status filter
        if kyc_status_filter and data["kyc_status"] != kyc_status_filter:
            continue
        
        # Update statistics
        total_gross += data["total_withdrawn"]
        total_tds += data["total_tds"]
        
        if data["total_withdrawn"] >= 30000:
            count_above_30000 += 1
        else:
            count_below_30000 += 1
        
        user_data.append(data)

    # Sort by total_withdrawn descending
    user_data.sort(key=lambda x: x['total_withdrawn'], reverse=True)

    # Pagination: 50 per page
    paginator = Paginator(user_data, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Generate list of financial years from earliest withdrawal to current
    years_set = set()
    all_withdrawals = WithdrawalTransaction.objects.filter(status='Transferred')
    for tx in all_withdrawals:
        tx_year = tx.created_at.year
        if tx.created_at.month < 4:
            tx_year -= 1
        years_set.add(tx_year)
    
    # Add current FY if not present
    current_fy = datetime.now().year if datetime.now().month >= 4 else datetime.now().year - 1
    years_set.add(current_fy)
    
    financial_years = sorted(list(years_set))

    context = {
        "page_obj": page_obj,
        "financial_years": financial_years,
        "selected_year": selected_year,
        "total_deductees": len(user_data),
        "total_gross": round(total_gross, 2),
        "total_tds": round(total_tds, 2),
        "total_net": round(total_gross - total_tds, 2),
        "count_above_30000": count_above_30000,
        "count_below_30000": count_below_30000,
        "request": request
    }

    return render(request, "tax_summary.html", context)






def transaction_list_view(request):
    search_query = request.GET.get('search', '')
    transactions = WithdrawalTransaction.objects.select_related('user')

    if search_query:
        transactions = transactions.filter(user__username__icontains=search_query)

    context = {
        'transactions': transactions.order_by('-created_at'),
        'search_query': search_query,
    }
    return render(request, 'transaction_list.html', context)



# views.py


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_ping(request):
    user = request.user
    user.last_seen = timezone.now()
    user.is_online = True  # You can keep this for better syncing
    user.save(update_fields=['last_seen', 'is_online'])
    return Response({'status': 'pong'})







logger = logging.getLogger(__name__)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def online_girls_busy_status(request):
    try:
        girls = User.objects.filter(is_online=True, is_girl=True)

        data = [
            {
                'username': girl.username,
                'is_busy': girl.is_busy,
                'created_at': girl.created_at.isoformat() if girl.created_at else None,
            }
            for girl in girls
        ]

        logger.info(f"[📊] Returned {len(data)} online girl busy statuses.")
        return Response({'online_users': data})

    except Exception as e:
        logger.error(f"[❌] Error in online_girls_busy_status: {e}", exc_info=True)
        return Response({'error': 'Something went wrong'}, status=500)






@api_view(['POST'])
@permission_classes([IsAuthenticated])
def set_user_offline(request):
    user = request.user
    user.is_online = False
    user.is_busy = False
    user.in_call_with = None
    user.last_seen = timezone.now()
    user.save()
    return Response({"status": "User marked offline"})






@api_view(['POST'])
@permission_classes([IsAuthenticated])
def track_mutual_time(request):
    """
    ✅ Save mutual_connected_seconds to the Call object.
    Requires: target_username, mutual_seconds
    """
    user = request.user
    target_username = request.data.get("target_username")
    mutual_seconds = request.data.get("mutual_seconds")

    if not target_username or mutual_seconds is None:
        return Response({"success": False, "message": "target_username and mutual_seconds are required."}, status=400)

    try:
        mutual_seconds = int(mutual_seconds)
    except ValueError:
        return Response({"success": False, "message": "mutual_seconds must be an integer."}, status=400)

    target = User.objects.filter(username=target_username).first()
    if not target:
        return Response({"success": False, "message": "Target user not found."}, status=404)

    call = Call.objects.filter(
        Q(caller=user, receiver=target) | Q(caller=target, receiver=user),
        active=True
    ).first()

    if not call:
        return Response({"success": False, "message": "Active call not found."}, status=404)

    call.mutual_connected_seconds = mutual_seconds
    call.save()

    return Response({"success": True, "message": "Mutual connected seconds saved."})