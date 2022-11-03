from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from jwt_auth.settings import jwt_auth_settings
from jwt_auth.utils import decode_token, check_expired_token

User = get_user_model()


class JWTAuthBackend(BaseAuthentication):
    def authenticate(self, request):
        if request.META.get("HTTP_AUTHORIZATION"):
            _, token = request.META.get("HTTP_AUTHORIZATION", "").split(" ")
            decoded_token = decode_token(token)
            if not decoded_token:
                raise AuthenticationFailed(detail="You use wrong token")
            store_token = jwt_auth_settings.STORE_TOKEN_BACKEND()
            token_obj = None
            token_obj = store_token.get(jti=decoded_token.get("jti"))
            if not token_obj:
                raise AuthenticationFailed(detail="You use wrong token")
            is_expired = check_expired_token(decoded_token.get("exp"))
            if is_expired:
                raise AuthenticationFailed(detail="Your token was expired")
            user = User.objects.filter(id=decoded_token.get("id")).first()
            return (user, token)
