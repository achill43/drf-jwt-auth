from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework import permissions
from rest_framework.exceptions import NotAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from jwt_auth.serializers import LoginSerializer, RefreshTokenSerializer
from jwt_auth.settings import jwt_auth_settings
from jwt_auth.utils import decode_token, generate_response


User = get_user_model()


class LoginView(APIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.user
            store_token_backend = jwt_auth_settings.STORE_TOKEN_BACKEND()
            token, user = store_token_backend.create(user)
            data = generate_response(token, user)
            return Response(data=data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        if request.META.get("HTTP_AUTHORIZATION"):
            _, token = request.META.get("HTTP_AUTHORIZATION", "").split(" ")
            decoded_token = decode_token(token)
            store_token = jwt_auth_settings.STORE_TOKEN_BACKEND()
            store_token.delete(jti=decoded_token.get("jti"))
            return Response(status=status.HTTP_200_OK)
        raise NotAuthenticated(detail="You token was expired")


class VerifyTokenView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        if request.META.get("HTTP_AUTHORIZATION"):
            _, token = request.META.get("HTTP_AUTHORIZATION", "").split(" ")
            decoded_token = decode_token(token)
            store_token = jwt_auth_settings.STORE_TOKEN_BACKEND()
            token_obj, user = store_token.get(jti=decoded_token.get("jti"))
            response = generate_response(token_obj, user)
            return Response(data=response, status=status.HTTP_200_OK)
        raise NotAuthenticated(detail="You token was expired")


class RefreshTokenView(APIView):
    serializer_class = RefreshTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            decoded_token = decode_token(serializer.data.get("refresh_token"))
            store_token = jwt_auth_settings.STORE_TOKEN_BACKEND()
            token_obj, user = store_token.update(jti=decoded_token.get("jti"))
            response = generate_response(token_obj, user)
            return Response(data=response, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
