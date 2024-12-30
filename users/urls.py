from django.urls import path
from django.contrib.auth.views import LogoutView
from . import views

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('home/', views.home_view, name='home'),
    path('logout/', LogoutView.as_view(next_page='login'), name='logout'),
    path('change-password/', views.change_password_view, name='change_password'),
    # Add other paths as needed
]
