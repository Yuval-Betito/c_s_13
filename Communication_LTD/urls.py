from django.contrib import admin
from django.urls import path, include
from users import views as user_views  # Renamed to avoid confusion

urlpatterns = [
    path("admin/", admin.site.urls),
    path('users/', include('users.urls')),  # Include user-specific URLs
    path('', user_views.home, name='home'),  # Home page route
]

