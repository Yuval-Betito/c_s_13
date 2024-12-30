from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import os
import hmac
import hashlib
from django.core.validators import RegexValidator


class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        if not email:
            raise ValueError("Users must have an email address")
        email = self.normalize_email(email)
        user = self.model(username=username, email=email)
        if password:
            user.set_password(password)  # Use the customized password hashing
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password):
        user = self.create_user(username, email, password)
        user.is_admin = True
        user.is_superuser = True  # Set superuser permissions
        user.is_staff = True        # Set staff permissions
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)      # Added is_staff field
    is_superuser = models.BooleanField(default=False)  # Added is_superuser field

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def set_password(self, raw_password):
        """Override set_password to use HMAC + Salt"""
        if raw_password:
            salt = os.urandom(16).hex()  # Generate a random Salt
            hashed_password = hmac.new(salt.encode(), raw_password.encode(), hashlib.sha256).hexdigest()
            self.password = f'{salt}${hashed_password}'  # Save salt and hash in the format: salt$hashed_password'

    def check_password(self, raw_password):
        """Verify the user's password"""
        if not self.password:
            return False
        try:
            salt, stored_hash = self.password.split('$')
            entered_hash = hmac.new(salt.encode(), raw_password.encode(), hashlib.sha256).hexdigest()
            return stored_hash == entered_hash
        except ValueError:
            return False

    def __str__(self):
        return self.username

    # Permissions methods required by Django admin
    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return self.is_admin


class Customer(models.Model):
    firstname = models.CharField(max_length=50)
    lastname = models.CharField(max_length=50)
    customer_id = models.CharField(max_length=10, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    phone_number = models.CharField(
        max_length=10,
        validators=[
            RegexValidator(
                regex=r'^05\d{8}$',
                message='Enter a valid Israeli phone number starting with 05.',
                code='invalid_phone_number'
            ),
        ],
    )

    def __str__(self):
        return f"{self.firstname} {self.lastname} ({self.customer_id})"


