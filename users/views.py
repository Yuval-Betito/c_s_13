from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.conf import settings
from django.core.cache import cache
from .forms import RegisterForm, LoginForm, PasswordChangeCustomForm, CustomerForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from .models import PasswordHistory  # If you implement password history

def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Registration successful! You can now log in.')
            return redirect('login')  # Ensure you have a URL named 'login'
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = RegisterForm()
    return render(request, 'users/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        username = request.POST.get('username')
        cache_key = f'login_attempts_{username}'
        attempts = cache.get(cache_key, 0)

        if attempts >= settings.PASSWORD_CONFIG['login_attempts']:
            messages.error(request, 'You have reached the maximum number of login attempts. Please try again later.')
            return render(request, 'users/login.html', {'form': form})

        if form.is_valid():
            user = form.get_user()
            login(request, user)
            cache.delete(cache_key)  # Reset the number of attempts after successful login
            return redirect('home')  # Ensure you have a URL named 'home'
        else:
            attempts += 1
            cache.set(cache_key, attempts, timeout=300)  # Lockout for 5 minutes
            remaining_attempts = settings.PASSWORD_CONFIG['login_attempts'] - attempts
            messages.error(request, f'Invalid username or password. You have {remaining_attempts} attempts remaining.')
    else:
        form = LoginForm()
    return render(request, 'users/login.html', {'form': form})

@login_required
def home_view(request):
    return render(request, 'users/home.html')

@login_required
def change_password_view(request):
    if request.method == 'POST':
        form = PasswordChangeCustomForm(request.POST, initial={'user': request.user})
        if form.is_valid():
            old_password = form.cleaned_data.get('old_password')
            new_password = form.cleaned_data.get('new_password')
            user = authenticate(username=request.user.username, password=old_password)
            if user:
                # Save current password to history before changing
                PasswordHistory.objects.create(user=user, password=user.password)

                user.set_password(new_password)
                user.save()
                update_session_auth_hash(request, user)  # Important to keep the session active
                messages.success(request, 'Your password has been successfully changed!')
                return redirect('home')
            else:
                messages.error(request, 'The current password is incorrect.')
    else:
        form = PasswordChangeCustomForm()
    return render(request, 'users/change_password.html', {'form': form})

# Add other views as needed
