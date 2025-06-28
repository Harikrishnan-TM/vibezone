from rest_framework import serializers
from .models import KYC

from .models import CallHistory
from .models import WalletTransaction

import logging




class KYCSerializer(serializers.ModelSerializer):
    class Meta:
        model = KYC
        fields = [
            'name',
            'mobile_number',     # ✅ Add this
            'pan_number',        # ✅ Add this
            'bank_name',
            'account_number',               
            'ifsc_code',
            'pan_card_image_url',  # ✅ use URL field instead
            'kyc_status'
        ]
    
    def validate_pan_number(self, value):
        pan = value.upper().strip()

        # If updating an existing KYC, exclude self
        if self.instance:
            exists = KYC.objects.exclude(pk=self.instance.pk).filter(pan_number=pan).exists()
        else:
            exists = KYC.objects.filter(pan_number=pan).exists()

        if exists:
            raise serializers.ValidationError("❌ This PAN number is already registered.")
        return pan

    def create(self, validated_data):
        validated_data['pan_number'] = validated_data['pan_number'].upper().strip()
        return super().create(validated_data)

    def update(self, instance, validated_data):
        if 'pan_number' in validated_data:
            validated_data['pan_number'] = validated_data['pan_number'].upper().strip()
        return super().update(instance, validated_data)



class WalletTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = WalletTransaction
        fields = ['type', 'coins', 'description', 'created_at']


# serializers.py updating updating







# Set up logger
logger = logging.getLogger(__name__)

class CallHistorySerializer(serializers.ModelSerializer):
    caller = serializers.CharField(source='caller.username', read_only=True)
    receiver = serializers.CharField(source='receiver.username', read_only=True)
    timestamp = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)

    class Meta:
        model = CallHistory
        fields = ['id', 'caller', 'receiver', 'timestamp']

    def to_representation(self, instance):
        data = super().to_representation(instance)
        logger.info(f"📦 Serialized CallHistory: {data}")
        return data

