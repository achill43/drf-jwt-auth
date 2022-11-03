import jwt
from jwt.exceptions import DecodeError
from datetime import datetime, timedelta

from django.contrib.auth import get_user_model

from jwt_auth.settings import jwt_auth_settings

User = get_user_model()


def add_extend_encode_token_field(token_dict: dict, user: User) -> dict:
    response = token_dict
    for field in jwt_auth_settings.EXTEND_USER_ENCODED_TOKEN_FIELD:
        response[field] = getattr(user, field)
    return response


def generate_token(user: User, jti: str, live_time: int, token_type: str) -> str:
    date_exp = (datetime.now() + timedelta(seconds=live_time)).timestamp()
    token_dict = {
        "id": user.id,
        "exp": date_exp,
        "jti": jti,
        "token_type": token_type,
    }
    token_dict = add_extend_encode_token_field(token_dict, user)
    token = jwt.encode(token_dict, jwt_auth_settings.SECRET_KEY, algorithm="HS256")
    return token


def generate_response(user_token, user):
    if user_token:
        response = dict()
        for field in jwt_auth_settings.RESPONSE_FIELDS:
            if "user__" in field:
                user_field = field.replace("user__", "")
                response[field] = getattr(user, user_field)
            else:
                response[field] = getattr(user_token, field)
        return response
    return None


def decode_token(token: str) -> dict:
    try:
        decoded_token = jwt.decode(
            token, jwt_auth_settings.SECRET_KEY, options={"verify_signature": False}
        )
    except DecodeError:
        return None
    return decoded_token


def check_expired_token(timestamp: int) -> bool:
    date_time_obj = datetime.fromtimestamp(int(timestamp))
    now = datetime.now()
    return date_time_obj < now
