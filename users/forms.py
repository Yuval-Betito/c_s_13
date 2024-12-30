from django import forms
from .models import User,Customer
import json
import re
from django.core.exceptions import ValidationError
from django.conf import settings  # Import settings to access BASE_DIR

class RegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def clean_password(self):
        password = self.cleaned_data.get('password')

        # Load configuration from the JSON file using BASE_DIR
        with open(settings.BASE_DIR / 'password_config.json', 'r') as f:  # Using BASE_DIR to ensure correct path
            config = json.load(f)

        # Check password length
        if len(password) < config['min_length']:
            raise ValidationError(f"Password must be at least {config['min_length']} characters long.")

        # Check for uppercase, lowercase, digits, and special characters
        if config['require_uppercase'] and not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain at least one uppercase letter.")
        if config['require_lowercase'] and not re.search(r'[a-z]', password):
            raise ValidationError("Password must contain at least one lowercase letter.")
        if config['require_digit'] and not re.search(r'\d', password):
            raise ValidationError("Password must contain at least one digit.")
        if config['require_special'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError("Password must contain at least one special character.")

        return password

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        if password != confirm_password:
            raise ValidationError("Passwords do not match.")

    def save(self, commit=True):
        user = super().save(commit=False)
        password = self.cleaned_data.get('password')
        user.set_password(password)  # Use the overridden set_password method
        if commit:
            user.save()
        return user


class PasswordChangeCustomForm(forms.Form):
    """Custom form for password change."""
    old_password = forms.CharField(widget=forms.PasswordInput, label="Current Password")
    new_password = forms.CharField(widget=forms.PasswordInput, label="New Password")
    confirm_new_password = forms.CharField(widget=forms.PasswordInput, label="Confirm New Password")

    def clean_new_password(self):
        new_password = self.cleaned_data.get('new_password')

        # Load configuration from the JSON file
        with open(settings.BASE_DIR / 'password_config.json', 'r') as f:
            config = json.load(f)

        # Check password length
        if len(new_password) < config['min_length']:
            raise ValidationError(f"Password must be at least {config['min_length']} characters long.")

        # Check for uppercase, lowercase, digits, and special characters
        if config['require_uppercase'] and not re.search(r'[A-Z]', new_password):
            raise ValidationError("Password must contain at least one uppercase letter.")
        if config['require_lowercase'] and not re.search(r'[a-z]', new_password):
            raise ValidationError("Password must contain at least one lowercase letter.")
        if config['require_digit'] and not re.search(r'\d', new_password):
            raise ValidationError("Password must contain at least one digit.")
        if config['require_special'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
            raise ValidationError("Password must contain at least one special character.")

        return new_password

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_new_password = cleaned_data.get('confirm_new_password')
        if new_password != confirm_new_password:
            raise ValidationError("New passwords do not match.")


class CustomerForm(forms.ModelForm):
    class Meta:
        model = Customer
        fields = ['firstname', 'lastname', 'customer_id', 'phone_number', 'email']  # השדות בטופס

    def __init__(self, *args, **kwargs):
        super(CustomerForm, self).__init__(*args, **kwargs)
        # הגדרת ערך ברירת מחדל לשדה phone_number
        self.fields['phone_number'].widget.attrs.update({'value': '05'})

    def save(self, commit=True):
        customer = super().save(commit=False)  # שמירת אובייקט בלי לכתוב אותו למסד הנתונים מיד
        if commit:
            customer.save()  # שמירה למסד הנתונים אם commit=True
        return customer
