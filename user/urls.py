from django.urls import path
from .views import (
    CreateUserAPIView,
    VerifyApiView,
    GetNewVerification,
    ChangeUserView,
    LoginView,
    CustomTokenRefreshView,
    LogoutView
)

urlpatterns = [
    path('signup/', CreateUserAPIView.as_view(), name='signup'),
    path('verify/', VerifyApiView.as_view(), name='verify_code'),
    path('new-verify/', GetNewVerification.as_view(), name='new_verify_code'),
    path('change-user-info/', ChangeUserView.as_view(), name='change_user_info'),
    path('login/', LoginView.as_view(), name='login'),
    path('login-refresh/', CustomTokenRefreshView.as_view(), name='refresh_token'),
    path('logout/', LogoutView.as_view(), name='logout'),
]