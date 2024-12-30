from django import forms
from django.contrib.auth.forms import AuthenticationForm
from .models import User, Customer
import json
import re
from django.core.exceptions import ValidationError
from django.conf import settings  # Import settings to access BASE_DIR


class RegisterForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput,
        label="Password",
        help_text="Password must be at least 10 characters long and include uppercase letters, lowercase letters, digits, and special characters."
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput,
        label="Confirm Password"
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        labels = {
            'username': 'Username',
            'email': 'Email',
        }

    def clean_password(self):
        password = self.cleaned_data.get('password')

        # Load configuration from the JSON file using BASE_DIR
        config_path = settings.BASE_DIR / 'password_config.json'
        with open(config_path, 'r') as f:
            config = json.load(f)

        # Check password length
        if len(password) < config['password_length']:
            raise ValidationError(f"Password must be at least {config['password_length']} characters long.")

        # Check for uppercase, lowercase, digits, and special characters
        complexity = config['password_complexity']
        if complexity['uppercase'] and not re.search(r'[A-Z]', password):
            raise ValidationError("Password must include uppercase letters.")
        if complexity['lowercase'] and not re.search(r'[a-z]', password):
            raise ValidationError("Password must include lowercase letters.")
        if complexity['digits'] and not re.search(r'\d', password):
            raise ValidationError("Password must include digits.")
        if complexity['special_characters'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError("Password must include special characters.")

        # Prevent using common passwords if enabled
        if config.get('prevent_dictionary', False):
            common_passwords_path = settings.BASE_DIR / 'common_passwords.txt'
            try:
                with open(common_passwords_path, 'r') as f:
                    common_passwords = f.read().splitlines()
                if password.lower() in [p.lower() for p in common_passwords]:
                    raise ValidationError("Your password is too common. Please choose a different password.")
            except FileNotFoundError:
                # If the dictionary file does not exist, you can skip or raise a warning
                pass

        return password

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError("This email is already in use. Please choose a different email.")
        return email

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        if password and confirm_password and password != confirm_password:
            raise ValidationError("Passwords do not match.")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        password = self.cleaned_data.get('password')
        user.set_password(password)  # Django handles hashing and salting
        if commit:
            user.save()
            # You can add password history saving here if you have a suitable model
        return user


class LoginForm(AuthenticationForm):
    username = forms.CharField(
        label="Username",
        max_length=150,
        widget=forms.TextInput(attrs={'autofocus': True, 'class': 'form-control'})
    )
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    )


class PasswordChangeCustomForm(forms.Form):
    """Custom form for changing passwords."""
    old_password = forms.CharField(
        widget=forms.PasswordInput,
        label="Current Password"
    )
    new_password = forms.CharField(
        widget=forms.PasswordInput,
        label="New Password"
    )
    confirm_new_password = forms.CharField(
        widget=forms.PasswordInput,
        label="Confirm New Password"
    )

    def clean_new_password(self):
        new_password = self.cleaned_data.get('new_password')

        # Load configuration from the JSON file
        config_path = settings.BASE_DIR / 'password_config.json'
        with open(config_path, 'r') as f:
            config = json.load(f)

        # Check password length
        if len(new_password) < config['password_length']:
            raise ValidationError(f"New password must be at least {config['password_length']} characters long.")

        # Check for uppercase, lowercase, digits, and special characters
        complexity = config['password_complexity']
        if complexity['uppercase'] and not re.search(r'[A-Z]', new_password):
            raise ValidationError("New password must include uppercase letters.")
        if complexity['lowercase'] and not re.search(r'[a-z]', new_password):
            raise ValidationError("New password must include lowercase letters.")
        if complexity['digits'] and not re.search(r'\d', new_password):
            raise ValidationError("New password must include digits.")
        if complexity['special_characters'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
            raise ValidationError("New password must include special characters.")

        # Prevent using common passwords if enabled
        if config.get('prevent_dictionary', False):
            common_passwords_path = settings.BASE_DIR / 'common_passwords.txt'
            try:
                with open(common_passwords_path, 'r') as f:
                    common_passwords = f.read().splitlines()
                if new_password.lower() in [p.lower() for p in common_passwords]:
                    raise ValidationError("Your password is too common. Please choose a different password.")
            except FileNotFoundError:
                pass

        # Here you can add validation for password history if needed

        return new_password

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_new_password = cleaned_data.get('confirm_new_password')
        if new_password and confirm_new_password and new_password != confirm_new_password:
            raise ValidationError("New passwords do not match.")
        return cleaned_data


class CustomerForm(forms.ModelForm):
    class Meta:
        model = Customer
        fields = ['firstname', 'lastname', 'customer_id', 'phone_number', 'email']  # Fields in the form

    def __init__(self, *args, **kwargs):
        super(CustomerForm, self).__init__(*args, **kwargs)
        # Set default value for phone_number field
        self.fields['phone_number'].widget.attrs.update({'placeholder': '05', 'pattern': '^05[0-9]{8}$'})
        self.fields['phone_number'].help_text = 'Enter a valid Israeli phone number starting with 05.'

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')
        if not re.match(r'^05\d{8}$', phone_number):
            raise ValidationError("Invalid phone number.")
        return phone_number

    def save(self, commit=True):
        customer = super().save(commit=False)
        if commit:
            customer.save()
            self.save_m2m()  # To save ManyToMany fields if any
        return customer

