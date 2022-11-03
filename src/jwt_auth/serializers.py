from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers

from jwt_auth.settings import jwt_auth_settings
from jwt_auth.utils import decode_token, check_expired_token


User = get_user_model()


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, attrs):
        user = authenticate(username=attrs.get("username"), password=attrs.get("password"))
        if not user:
            raise ValueError("You use wrong credantions")
        self.user = user
        return attrs


class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, attrs):
        decoded_token = decode_token(attrs.get("refresh_token"))
        store_token = jwt_auth_settings.STORE_TOKEN_BACKEND()
        token = store_token.get(jti=decoded_token.get("jti"))
        if not token:
            raise ValueError("This token does not exist")
        is_expired = check_expired_token(decoded_token.get("exp"))
        if is_expired:
            raise ValueError(detail="Your refresh token was expired")
        return attrs
