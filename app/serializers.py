from rest_framework import serializers
from .models import KYC

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
