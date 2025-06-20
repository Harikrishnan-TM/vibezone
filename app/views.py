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

from rest_framework import generics, permissions
from .models import CallHistory
from .serializers import CallHistorySerializer

import traceback

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication


































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




def health_check(request):
    return JsonResponse({'status': 'ok'}, status=200)



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

    # ✅ Update target user
    target.incoming_call_from = request.user.username
    target.in_call_with = request.user  # assigning User instance
    target.is_busy = True
    target.save()

    # ✅ Update caller user
    request.user.in_call_with = target
    request.user.is_busy = True
    request.user.save()

    # ✅ Save call history
    from .models import CallHistory  # just in case
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
            success = user.wallet.deduct_coin(1)
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
        'coins': float(user.wallet.balance)
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
    coins_to_add = request.data.get('coins')

    try:
        coins_to_add = int(coins_to_add)
        if coins_to_add <= 0:
            raise ValueError("Coins must be a positive integer.")
    except (ValueError, TypeError):
        return Response(
            {'error': 'Please enter a valid number of coins.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    wallet = getattr(request.user, 'wallet', None)
    if not wallet:
        return Response(
            {'error': 'Wallet not found for user.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # ✅ Assume 1 coin = ₹1. Use Decimal to match model's precision.
    wallet.balance += Decimal(coins_to_add)
    wallet.save()

    return Response({
        'message': f'{coins_to_add} coins added to your wallet!',
        'balance': float(wallet.balance)  # ✅ Convert Decimal to float for JSON response jkl jkl
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





@api_view(['POST'])
@permission_classes([AllowAny])
def api_login(request):
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({'error': 'Username and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(username=username, password=password)
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



#login view only for the github website


@api_view(['POST'])
def website_login(request):
    username = request.data.get('username')
    password = request.data.get('password')

    user = authenticate(username=username, password=password)

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
    if request.method == 'POST':
        serializer = KYCSerializer(data=request.data)
        if serializer.is_valid():
            # Save KYC instance and associate with user
            kyc = serializer.save(user=request.user)

            # Handle PAN card upload
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
    rupees_equivalent = coins_requested * 1.0

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







@csrf_exempt
def razorpay_payment_success(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    payment_id = data.get('payment_id')
    order_id = data.get('order_id')
    signature = data.get('signature')
    amount = data.get('amount')
    user_id = data.get('user_id')

    if not all([payment_id, order_id, signature, amount, user_id]):
        return JsonResponse({'error': 'Missing required fields'}, status=400)

    try:
        # Verify user exists
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    # Verify Razorpay signature
    client = razorpay.Client(auth=(os.getenv("RAZORPAY_KEY_ID"), os.getenv("RAZORPAY_KEY_SECRET")))
    try:
        client.utility.verify_payment_signature({
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": signature
        })
    except razorpay.errors.SignatureVerificationError:
        return JsonResponse({'error': 'Invalid payment signature'}, status=400)

    # Credit balance
    wallet, _ = Wallet.objects.get_or_create(user=user)
    coins = Decimal(amount)  # assuming 1 INR = 1 coin
    wallet.balance += coins
    wallet.save()

    return JsonResponse({'message': 'Coins added successfully', 'balance': str(wallet.balance)})

















@csrf_exempt
def confirm_payment(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    try:
        # DEBUG: Print incoming headers
        print("📥 Incoming Headers:", request.headers)

        # Parse JSON body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON body"}, status=400)

        print("📦 Received payment data:", data)

        payment_id = data.get("payment_id")
        order_id = data.get("order_id")
        signature = data.get("signature")
        amount = data.get("amount")
        username = data.get("username")

        if not all([payment_id, order_id, signature, amount, username]):
            return JsonResponse({"error": "Missing required fields"}, status=400)

        # Get user by username
        try:
            user = User.objects.get(username=username)
            print(f"✅ Identified user by username: {user.username}")
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
            print("✅ Razorpay signature verified.")
        except razorpay.errors.SignatureVerificationError:
            print("❌ Razorpay signature verification failed.")
            return JsonResponse({"error": "Payment signature invalid"}, status=400)

        # Credit balance to wallet (used for calling girls)
        coins_to_credit = Decimal(amount)
        wallet, _ = Wallet.objects.get_or_create(user=user)
        wallet.balance += coins_to_credit
        wallet.save()

        print(f"💰 Credited ₹{coins_to_credit} to {user.username}. New balance: ₹{wallet.balance}")

        return JsonResponse({
            "message": "Coins credited successfully",
            "balance": str(wallet.balance)
        })

    except Exception as e:
        print("🔥 Exception during confirm_payment:", str(e))
        return JsonResponse({"error": str(e)}, status=500)





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

