import uuid
import hmac
from hashlib import sha1
from django.db import models


class TokenManager(models.Manager):
    """
    Manager class to provide `Token.objects.create_token(user=user)`.
    """
    def create_token(self, user):
        token = Token(user=user)
        token.save()
        return token


class Token(models.Model):
    """
    The default authorization token model.
    """
    key = models.CharField(max_length=40, primary_key=True)
    user = models.ForeignKey('auth.User')
    revoked = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    objects = TokenManager()

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super(Token, self).save(*args, **kwargs)

    def generate_key(self):
        unique = str(uuid.uuid4())
        return hmac.new(unique, digestmod=sha1).hexdigest()
