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
    target.in_call_with = request.user  # ✅ was username; now assign User instance
    target.is_busy = True
    target.save()

    # ✅ Update caller user
    request.user.in_call_with = target  # ✅ was username; now assign User instance
    request.user.is_busy = True
    request.user.save()

    return Response({
        'message': 'Call initiated successfully.',
        'other_user': target.username,
        'wallet_balance': request.user.wallet.balance if hasattr(request.user, 'wallet') else 0,  # ✅ updated key + field
        'is_initiator': True,
        'redirect': '/call'  # Flutter will navigate to CallScreen
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
    target = User.objects.filter(username=target_username).first()

    if not target:
        return Response({'success': False, 'message': 'Target user not found.'}, status=400)

    # 🔵 Reset statuses for both users (caller and receiver)
    for u in [user, target]:
        u.in_call_with = None  # ✅ Updated for ForeignKey field
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

    return Response({"success": True})







@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deduct_coins(request):
    user = request.user

    if user.in_call_with:  # User is in a call
        if user.is_girl:
            # Add to withdrawable earnings (earnings_coins), not spendable balance
            user.wallet.add_earnings(1)
        else:
            # Deduct from spendable balance (balance)
            success = user.wallet.deduct_coin(1)
            if not success:
                return Response({
                    'end_call': True,
                    'message': 'Insufficient coins'
                }, status=402)  # 402 = Payment Required

    return Response({
        'success': True,
        'coins': float(user.wallet.balance)  # Return updated spendable balance
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
            user.is_girl = is_girl  # ✅ FIXED THIS LINE
            user.save()

            token, _ = Token.objects.get_or_create(user=user)
            return JsonResponse({'token': token.key}, status=201)


            

        except OperationalError:
            return JsonResponse({'message': 'Database error. Please try again later.'}, status=500)
        except Exception as e:
            return JsonResponse({'message': f'Unexpected error: {str(e)}'}, status=500)

    return JsonResponse({'message': 'Invalid request method.'}, status=405)



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




# views.py






@api_view(['POST'])
@permission_classes([IsAuthenticated])
def submit_kyc(request):
    if request.method == 'POST':
        serializer = KYCSerializer(data=request.data)
        if serializer.is_valid():
            # Save KYC instance but don't commit to DB yet
            kyc = serializer.save(commit=False)
            kyc.user = request.user  # ✅ Associate the logged-in user with the KYC
            kyc.save()

            # Handle PAN card upload
            pan_card_image = request.FILES.get('pan_card_image')
            if pan_card_image:
                file_url = upload_file_to_supabase(pan_card_image)
                kyc.pan_card_image_url = file_url
                kyc.save()

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

    # Calculate rupee equivalent (assuming 1 coin = ₹1, adjust if needed)
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

