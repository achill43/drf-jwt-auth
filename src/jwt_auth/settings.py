from rest_framework.settings import APISettings
from django.conf import settings

USER_SETTINGS = getattr(settings, 'JWT_AUTH', None)

DEFAULTS = {
    "SECRET_KEY": settings.SECRET_KEY,
    "STORE_TOKEN_BACKEND": "jwt_auth.store_backend.StoreTokenDatabase",
    "LOGIN_SERIALIZER": "jwt_auth.serializers.LoginSerializer",
    "RESPONSE_FIELDS": ["access", "refresh", "user__username"],
    "ACCESS_TOKEN_LIVE": 3600,
    "REFRESH_TOKEN_LIVE": 86400,
    "ROTATE_REFRESH_TOKEN": False,
    "EXTEND_USER_ENCODED_TOKEN_FIELD": ["username"],
}
IMPORT_STRINGS = (
    "STORE_TOKEN_BACKEND",
    "LOGIN_SERIALIZER",
)


jwt_auth_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
