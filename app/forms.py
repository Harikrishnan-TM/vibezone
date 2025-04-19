from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User

class CustomUserCreationForm(UserCreationForm):
    GENDER_CHOICES = [
        (False, 'Boy'),
        (True, 'Girl'),
    ]

    is_girl = forms.ChoiceField(choices=GENDER_CHOICES, widget=forms.RadioSelect, label="I am a")

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2', 'is_girl')
