from django.urls import path

from jwt_auth.views import LoginView, LogoutView, RefreshTokenView, VerifyTokenView


urlpatterns = [
    path("login/", LoginView.as_view()),
    path("logout/", LogoutView.as_view()),
    path("verify-token/", VerifyTokenView.as_view()),
    path("refresh-token/", RefreshTokenView.as_view()),
]
