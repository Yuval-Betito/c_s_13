from django.urls import path
from .views import register, user_login, home, create_customer

urlpatterns = [
    path('register/', register, name='register'),
    path('login/', user_login, name='login'),
    path('home/', home, name='home'),
    path('create_customer/', create_customer, name='create_customer'),
]
