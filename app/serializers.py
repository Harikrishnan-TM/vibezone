from rest_framework import serializers
from .models import KYC

from .models import CallHistory
from .models import WalletTransaction


class KYCSerializer(serializers.ModelSerializer):
    class Meta:
        model = KYC
        fields = [
            'name',
            'bank_name',
            'account_number',               
            'ifsc_code',
            'pan_card_image_url',  # ✅ use URL field instead
            'kyc_status'
        ]


class WalletTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = WalletTransaction
        fields = ['type', 'coins', 'description', 'created_at']


# serializers.py


class CallHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = CallHistory
        fields = '__all__'
