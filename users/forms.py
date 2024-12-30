from django import forms
from .models import User, Customer
import json
import re
from django.core.exceptions import ValidationError
from django.conf import settings  # Import settings to access BASE_DIR

class RegisterForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput,
        label="סיסמא",
        help_text="הסיסמא חייבת להיות לפחות 10 תווים ולכלול אותיות גדולות, קטנות, ספרות ותווים מיוחדים."
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput,
        label="אימות סיסמא"
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        labels = {
            'username': 'שם משתמש',
            'email': 'אימייל',
        }

    def clean_password(self):
        password = self.cleaned_data.get('password')

        # Load configuration from the JSON file using BASE_DIR
        config_path = settings.BASE_DIR / 'password_config.json'
        with open(config_path, 'r') as f:
            config = json.load(f)

        # Check password length
        if len(password) < config['password_length']:
            raise ValidationError(f"הסיסמה חייבת להיות לפחות {config['password_length']} תווים.")

        # Check for uppercase, lowercase, digits, and special characters
        complexity = config['password_complexity']
        if complexity['uppercase'] and not re.search(r'[A-Z]', password):
            raise ValidationError("הסיסמה חייבת לכלול אותיות גדולות.")
        if complexity['lowercase'] and not re.search(r'[a-z]', password):
            raise ValidationError("הסיסמה חייבת לכלול אותיות קטנות.")
        if complexity['digits'] and not re.search(r'\d', password):
            raise ValidationError("הסיסמה חייבת לכלול ספרות.")
        if complexity['special_characters'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError("הסיסמה חייבת לכלול תווים מיוחדים.")

        # Prevent using common passwords if enabled
        if config.get('prevent_dictionary', False):
            common_passwords_path = settings.BASE_DIR / 'common_passwords.txt'
            try:
                with open(common_passwords_path, 'r') as f:
                    common_passwords = f.read().splitlines()
                if password.lower() in [p.lower() for p in common_passwords]:
                    raise ValidationError("הסיסמה שלך נפוצה מדי, אנא בחר סיסמה אחרת.")
            except FileNotFoundError:
                # Log a warning or handle as needed
                pass

        return password

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError("אימייל זה כבר בשימוש. אנא בחר אימייל אחר.")
        return email

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        if password and confirm_password and password != confirm_password:
            raise ValidationError("הסיסמאות לא תואמות.")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        password = self.cleaned_data.get('password')
        user.set_password(password)  # Django מטפל ב-hashing ו-salt
        if commit:
            user.save()
            # ניתן להוסיף שמירת היסטוריית סיסמאות כאן אם יש מודל מתאים
        return user

