from django.contrib.auth.models import AbstractUser
from django.db import models
from .utils import hash_password, verify_password

class User(AbstractUser):
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=128)
    can_create_user = models.BooleanField(default=False)
    
    # Add related_name to resolve conflicts
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_set',
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_set',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    @staticmethod
    def generate_password_hash(raw_password):
        return hash_password(raw_password)

    def set_password(self, raw_password):
        self.password_hash = self.generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return verify_password(raw_password, self.password_hash)

    class Meta:
        db_table = 'users' 