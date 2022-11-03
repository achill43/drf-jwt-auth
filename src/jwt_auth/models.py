from django.contrib.auth import get_user_model
from django.db import models
from django.utils.translation import ugettext_lazy as _


User = get_user_model()


class UserToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name=_("user"))
    jti = models.CharField(max_length=255, verbose_name=_("jti"))
    access = models.CharField(max_length=450, verbose_name=_("access"))
    refresh = models.CharField(max_length=450, verbose_name=_("refresh"))
    created_at = models.DateTimeField(auto_now_add=True, auto_now=False)

    class Meta:
        verbose_name = _("User`s Token")
        verbose_name_plural = _("User`s Tokens")
