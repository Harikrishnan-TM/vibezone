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


# -------------------- AUTH --------------------

def signup_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            user.is_online = not user.is_girl
            user.save()
            Wallet.objects.get_or_create(user=user)
            return redirect('home')
    else:
        form = CustomUserCreationForm()
    return render(request, 'signup.html', {'form': form})


class CustomLoginView(LoginView):
    template_name = 'login.html'

    def form_valid(self, form):
        response = super().form_valid(form)
        user = self.request.user
        user.is_online = not user.is_girl
        user.save()
        return response


def custom_logout_view(request):
    if request.user.is_authenticated:
        request.user.is_online = False
        request.user.incoming_call_from = ''
        request.user.in_call_with = None
        request.user.is_busy = False
        request.user.save()
    logout(request)
    return redirect('login')


# -------------------- MAIN VIEWS --------------------

@login_required
def home(request):
    call = Call.objects.filter(
        Q(caller=request.user) | Q(receiver=request.user),
        active=True
    ).first()

    if call:
        return redirect('call')

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

    return render(request, 'home.html', {
        'wallet': request.user.wallet,
        'user': request.user,
        'online_users': girls,
    })


@login_required
def online_users(request):
    if request.user.in_call_with:
        active_call = Call.objects.filter(
            Q(caller=request.user) | Q(receiver=request.user),
            active=True
        ).first()
        if active_call:
            return redirect('call')
        else:
            request.user.in_call_with = ''
            request.user.incoming_call_from = ''
            request.user.save()

    girls_online = User.objects.filter(
        is_online=True,
        is_girl=True
    ).exclude(id=request.user.id)

    return render(request, 'online_users.html', {
        'online_users': girls_online,
        'me': request.user
    })


# -------------------- CALL LOGIC --------------------

@login_required
def call_user(request, username):
    target = get_object_or_404(User, username=username)

    if target.in_call_with or not target.is_online:
        messages.error(request, f"{target.username} is currently unavailable.")
        return redirect('online_users')

    target.incoming_call_from = request.user.username
    target.in_call_with = request.user.username
    target.is_busy = True
    target.save()

    request.user.in_call_with = target.username
    request.user.is_busy = True
    request.user.save()

    return redirect('call')


@login_required
def call_view(request):
    user = request.user
    other_username = user.in_call_with

    if not other_username:
        return redirect('online_users')

    other_user = User.objects.filter(username=other_username).first()
    if not other_user:
        return redirect('online_users')

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

    return render(request, 'call.html', {
        'app_id': settings.AGORA_APP_ID,
        'username': user.username,
        'other_user': other_user.username,
        'is_girl': user.is_girl,
        'is_initiator': user.username == call.caller.username
    })


@csrf_exempt
@require_POST
@login_required
def accept_call(request):
    data = json.loads(request.body)
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

    return JsonResponse({'accepted': True})


@csrf_exempt
@require_POST
@login_required
def end_call(request):
    data = json.loads(request.body)
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

    return JsonResponse({"success": True})


# -------------------- COINS --------------------

@csrf_exempt
@login_required
def deduct_coins(request):
    user = request.user
    if user.in_call_with:
        if user.is_girl:
            user.wallet.add_coin(1)
        else:
            success = user.wallet.deduct_coin(1)
            if not success:
                return JsonResponse({'end_call': True})
    return JsonResponse({'success': True, 'coins': user.wallet.coins})


@csrf_exempt
@login_required
def buy_coins(request):
    if request.method == 'POST':
        coins_to_add = int(request.POST.get('coins', 0))
        if coins_to_add > 0:
            request.user.wallet.coins += coins_to_add
            request.user.wallet.save()
            messages.success(request, f'{coins_to_add} coins added to your wallet!')
            return redirect('home')
        else:
            messages.error(request, 'Please enter a valid number of coins.')
    return render(request, 'buy_coins.html')


@login_required
def get_wallet_balance(request):
    return JsonResponse({'coins': request.user.wallet.coins})


# -------------------- UTILITIES --------------------

@login_required
def toggle_online_status(request):
    if request.user.is_girl:
        request.user.is_online = not request.user.is_online
        request.user.save()
    return redirect('home')


@login_required
def profile_view(request):
    return render(request, 'profile.html')


@login_required
def online_users_partial(request):
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

    return render(request, "partials/online_list.html", {
        'online_users': girls,
        'me': request.user,
    })


# -------------------- API ENDPOINTS --------------------

@login_required
def check_call_status(request):
    call = Call.objects.filter(
        Q(caller=request.user) | Q(receiver=request.user),
        active=True
    ).first()
    return JsonResponse({'in_call': bool(call)})


@login_required
def check_incoming_call(request):
    if not request.user.is_girl:
        return JsonResponse({'being_called': False})

    incoming = Call.objects.filter(
        receiver=request.user,
        active=True,
        accepted=False
    ).exists()

    return JsonResponse({'being_called': incoming})


@api_view(['GET'])
def hello_world(request):
    return Response({"message": "Hello from Django API!"})
