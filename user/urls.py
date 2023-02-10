from django.urls import path
from .views import (
    CreateUserAPIView,
    VerifyApiView,
    GetNewVerification
)

urlpatterns = [
    path('signup/', CreateUserAPIView.as_view(), name='signup'),
    path('verify/', VerifyApiView.as_view(), name='verify_code'),
    path('new-verify/', GetNewVerification.as_view(), name='new_verify_code')
]