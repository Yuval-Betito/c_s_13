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
            raise ValidationError(f"הסיסמא חייבת להיות לפחות {config['password_length']} תווים.")

        # Check for uppercase, lowercase, digits, and special characters
        complexity = config['password_complexity']
        if complexity['uppercase'] and not re.search(r'[A-Z]', password):
            raise ValidationError("הסיסמא חייבת לכלול אותיות גדולות.")
        if complexity['lowercase'] and not re.search(r'[a-z]', password):
            raise ValidationError("הסיסמא חייבת לכלול אותיות קטנות.")
        if complexity['digits'] and not re.search(r'\d', password):
            raise ValidationError("הסיסמא חייבת לכלול ספרות.")
        if complexity['special_characters'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError("הסיסמא חייבת לכלול תווים מיוחדים.")

        # Prevent using common passwords if enabled
        if config.get('prevent_dictionary', False):
            common_passwords_path = settings.BASE_DIR / 'common_passwords.txt'
            try:
                with open(common_passwords_path, 'r') as f:
                    common_passwords = f.read().splitlines()
                if password.lower() in [p.lower() for p in common_passwords]:
                    raise ValidationError("הסיסמא שלך נפוצה מדי, אנא בחר סיסמא אחרת.")
            except FileNotFoundError:
                # אם קובץ המילון לא קיים, ניתן לדלג או לזרוק אזהרה
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


class LoginForm(AuthenticationForm):
    username = forms.CharField(
        label="שם משתמש",
        max_length=150,
        widget=forms.TextInput(attrs={'autofocus': True, 'class': 'form-control'})
    )
    password = forms.CharField(
        label="סיסמא",
        strip=False,
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    )


class PasswordChangeCustomForm(forms.Form):
    """טופס מותאם אישית לשינוי סיסמא."""
    old_password = forms.CharField(
        widget=forms.PasswordInput,
        label="סיסמא נוכחית"
    )
    new_password = forms.CharField(
        widget=forms.PasswordInput,
        label="סיסמא חדשה"
    )
    confirm_new_password = forms.CharField(
        widget=forms.PasswordInput,
        label="אימות סיסמא חדשה"
    )

    def clean_new_password(self):
        new_password = self.cleaned_data.get('new_password')

        # Load configuration from the JSON file
        config_path = settings.BASE_DIR / 'password_config.json'
        with open(config_path, 'r') as f:
            config = json.load(f)

        # Check password length
        if len(new_password) < config['password_length']:
            raise ValidationError(f"הסיסמא חייבת להיות לפחות {config['password_length']} תווים.")

        # Check for uppercase, lowercase, digits, and special characters
        complexity = config['password_complexity']
        if complexity['uppercase'] and not re.search(r'[A-Z]', new_password):
            raise ValidationError("הסיסמא חייבת לכלול אותיות גדולות.")
        if complexity['lowercase'] and not re.search(r'[a-z]', new_password):
            raise ValidationError("הסיסמא חייבת לכלול אותיות קטנות.")
        if complexity['digits'] and not re.search(r'\d', new_password):
            raise ValidationError("הסיסמא חייבת לכלול ספרות.")
        if complexity['special_characters'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
            raise ValidationError("הסיסמא חייבת לכלול תווים מיוחדים.")

        # Prevent using common passwords if enabled
        if config.get('prevent_dictionary', False):
            common_passwords_path = settings.BASE_DIR / 'common_passwords.txt'
            try:
                with open(common_passwords_path, 'r') as f:
                    common_passwords = f.read().splitlines()
                if new_password.lower() in [p.lower() for p in common_passwords]:
                    raise ValidationError("הסיסמא שלך נפוצה מדי, אנא בחר סיסמא אחרת.")
            except FileNotFoundError:
                pass

        # כאן תוכל להוסיף ולידציה להיסטוריית סיסמאות במידת הצורך

        return new_password

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_new_password = cleaned_data.get('confirm_new_password')
        if new_password and confirm_new_password and new_password != confirm_new_password:
            raise ValidationError("הסיסמאות החדשות לא תואמות.")
        return cleaned_data


class CustomerForm(forms.ModelForm):
    class Meta:
        model = Customer
        fields = ['firstname', 'lastname', 'customer_id', 'phone_number', 'email']  # השדות בטופס

    def __init__(self, *args, **kwargs):
        super(CustomerForm, self).__init__(*args, **kwargs)
        # הגדרת ערך ברירת מחדל לשדה phone_number
        self.fields['phone_number'].widget.attrs.update({'placeholder': '05', 'pattern': '^05[0-9]{8}$'})
        self.fields['phone_number'].help_text = 'הזן מספר טלפון ישראלי תקין המתחיל ב-05'

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')
        if not re.match(r'^05\d{8}$', phone_number):
            raise ValidationError("מספר הטלפון אינו תקין.")
        return phone_number

    def save(self, commit=True):
        customer = super().save(commit=False)
        if commit:
            customer.save()
            self.save_m2m()  # לשמירת שדות ManyToMany אם יש
        return customer

