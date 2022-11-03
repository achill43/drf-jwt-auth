import datetime
import json

from abc import ABC
from dataclasses import dataclass
from uuid import uuid4

from django.conf import settings
from django.contrib.auth import get_user_model

from jwt_auth.context_managers import redis_connection
from jwt_auth.models import UserToken
from jwt_auth.settings import jwt_auth_settings
from jwt_auth.utils import generate_token

User = get_user_model()


@dataclass
class TokennRedisModel:
    user: User
    jti: str
    access: str
    refresh: str
    created_at: datetime.datetime

    def __init__(self, user_id: int, jti: str, access: str, refresh: str) -> None:
        self.user = User.objects.get(id=user_id)
        self.jti = jti
        self.access = access
        self.refresh = refresh
        self.created_at = datetime.datetime.now()

    def to_dict(self) -> dict:
        return {
            "user_id": self.user.id,
            "jti": self.jti,
            "access": self.access,
            "refresh": self.refresh
        }


class BaseStoreToken(ABC):

    def create(self, user: User) -> dict:
        """Create token for user

        Args:
            user (User): User model instance

        Returns:
            dict: includes fields which added in settings.RESPONSE_FIELDS
        """
        raise NotImplementedError

    def get(self, jti: str) -> dict:
        """Return user tokens dict with this token

        Args:
            jti (str): unique string for each token

        Returns:
            dict: includes fields which added in settings.RESPONSE_FIELDS
        """
        raise NotImplementedError

    def update(self, jti: str) -> dict:
        """Update user access token dict with this jti

        Args:
            jti (str): unique string for each token

        Returns:
            dict: includes fields which added in settings.RESPONSE_FIELDS
        """
        raise NotImplementedError

    def delete(self, jti: str) -> None:
        """Delete user token whith this jti

        Args:
            jti (str): _description_
        """
        raise NotImplementedError


class StoreTokenDatabase(BaseStoreToken):

    def create(self, user: User) -> tuple:
        """Create token for user

        Args:
            user (User): User model instance

        Returns:
            dict: includes fields which added in settings.RESPONSE_FIELDS
        """
        jti = uuid4().hex
        access_token = generate_token(
            user=user, jti=jti, live_time=jwt_auth_settings.ACCESS_TOKEN_LIVE, token_type="access")
        refresh_token = generate_token(
            user=user, jti=jti, live_time=jwt_auth_settings.REFRESH_TOKEN_LIVE, token_type="refresh")
        user_token = UserToken.objects.create(
            user=user, jti=jti, access=access_token, refresh=refresh_token
        )

        return (user_token, user_token.user)

    def get(self, jti: str) -> tuple:
        """Return user tokens dict with this jti

        Args:
            jti (str): unique string for each token

        Returns:
            dict: includes fields which added in settings.RESPONSE_FIELDS
        """
        user_token = UserToken.objects.filter(jti=jti).first()

        return (user_token, user_token.user)

    def update(self, jti: str) -> tuple:
        """Update user access token dict with this jti

        Args:
            jti (str): unique string for each token

        Returns:
            dict: includes fields which added in settings.RESPONSE_FIELDS
        """
        user_token = UserToken.objects.filter(jti=jti).first()
        user_token.access = generate_token(
            user=user_token.user, jti=jti, live_time=jwt_auth_settings.ACCESS_TOKEN_LIVE, token_type="access")
        if jwt_auth_settings.ROTATE_REFRESH_TOKEN:
            user_token.refresh = generate_token(
                user=user_token.user, jti=jti, live_time=jwt_auth_settings.REFRESH_TOKEN_LIVE, token_type="refresh")
        user_token.save()

        return (user_token, user_token.user)

    def delete(self, jti: str) -> None:
        """Delete user token whith this jti

        Args:
            jti (str): _description_
        """
        user_token = UserToken.objects.filter(jti=jti).first()
        user_token.delete()


class StoreTokenRedis(BaseStoreToken):

    def create(self, user: User) -> tuple:
        """Create token for user

        Args:
            user (User): User model instance

        Returns:
            dict: includes fields which added in settings.RESPONSE_FIELDS
        """
        jti = uuid4().hex
        access_token = generate_token(
            user=user, jti=jti, live_time=jwt_auth_settings.ACCESS_TOKEN_LIVE, token_type="access")
        refresh_token = generate_token(
            user=user, jti=jti, live_time=jwt_auth_settings.REFRESH_TOKEN_LIVE, token_type="refresh")
        token = TokennRedisModel(user_id=user.id, jti=jti, access=access_token, refresh=refresh_token)
        with redis_connection(host=settings.REDIS_HOST, port=settings.REDIS_PORT, password=settings.REDIS_PASS) as redis_client:
            redis_client.set(jti, json.dumps(token.to_dict()))
            redis_client.expire(jti, jwt_auth_settings.REFRESH_TOKEN_LIVE)
        return (token, user)


    def get(self, jti: str) -> tuple:
        """Return user tokens dict with this token

        Args:
            jti (str): unique string for each token

        Returns:
            dict: includes fields which added in settings.RESPONSE_FIELDS
        """
        with redis_connection(host=settings.REDIS_HOST, port=settings.REDIS_PORT, password=settings.REDIS_PASS) as redis_client:
            token = TokennRedisModel(**json.loads(redis_client.get(jti)))
        return (token, token.user)


    def update(self, jti: str) -> tuple:
        """Update user access token dict with this jti

        Args:
            jti (str): unique string for each token

        Returns:
            dict: includes fields which added in settings.RESPONSE_FIELDS
        """
        with redis_connection(host=settings.REDIS_HOST, port=settings.REDIS_PORT, password=settings.REDIS_PASS) as redis_client:
            token = TokennRedisModel(**json.loads(redis_client.get(jti)))
            user = token.user
            token.access = generate_token(
                user=user, jti=jti, live_time=jwt_auth_settings.ACCESS_TOKEN_LIVE, token_type="access")
            if jwt_auth_settings.ROTATE_REFRESH_TOKEN:
                token.refresh = generate_token(
                    user=user, jti=jti, live_time=jwt_auth_settings.REFRESH_TOKEN_LIVE, token_type="refresh")
            redis_client.set(jti, json.dumps(token.to_dict()))
            redis_client.expire(jti, jwt_auth_settings.REFRESH_TOKEN_LIVE)
        return (token, user)


    def delete(self, jti: str) -> None:
        """Delete user token whith this jti

        Args:
            jti (str): _description_
        """
        with redis_connection(host=settings.REDIS_HOST, port=settings.REDIS_PORT, password=settings.REDIS_PASS) as redis_client:
            redis_client.delete(jti)
