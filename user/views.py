from datetime import datetime
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework import generics
from shared.utils import send_email
from .models import (
    CustomUser,
    INFORMATION_FILLED,
    CODE_VERIFIED,
    DONE,
    VIA_EMAIL,
    VIA_PHONE
)
from .serializers import (
    SignUpSerializer,
    ChangeUserInformation
)


class CreateUserAPIView(CreateAPIView):
    model = CustomUser
    permission_classes = (permissions.AllowAny,)
    serializer_class = SignUpSerializer

    def get_queryset(self):
        return self.get_queryset()

class VerifyApiView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        user, code = self.request.user, request.data.get('code')
        self.check_verify(user, code)
        return Response(
            data={
                'success': True,
                'auth_status': user.auth_status,
                'access': user.token()['access'],
                'refresh': user.token()['refresh']
            },
            status=200
        )

    @staticmethod
    def check_verify(user, code):
        user_confirm_obj = user.verify_codes.filter(
            expiration_time__gte=datetime.now(),
            code=code,
            is_confirmed=False
        )
        if not user_confirm_obj.exists():
            data = {
                'message': 'Code is incorrect or expired!'
            }
            raise ValidationError(data)
        user_confirm_obj.update(is_confirmed=True)
        if user.auth_status not in (INFORMATION_FILLED, DONE):
            user.auth_status = CODE_VERIFIED
            user.save()
        return True

class GetNewVerification(APIView):
    permission_classes = (permissions.IsAuthenticated, )

    def get(self, request, *args, **kwargs):
        user = self.request.user
        self.check_verification(user)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            # send_phone_notification(user.phone_number, code)
            send_email(user.phone_number, code)
        else:
            data = {
                "message": "You need to enter email or phone_number",
            }
            raise ValidationError(data)
        return Response(
            {
                "success": True
            }
        )


    @staticmethod
    def check_verification(user):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), is_confirmed=False)
        if verifies.exists():
            data = {
                "message": "You need to wait over expiration time",
            }
            raise ValidationError(data)

class ChangeUserView(generics.UpdateAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = ChangeUserInformation
    http_method_names = ['patch', 'put']

    def partial_update(self, request, *args, **kwargs):
        super(ChangeUserView, self).partial_update(request, *args, **kwargs)
        return Response(
            data={
                'detail': 'Updated successfully',
                'auth_status': self.request.user.auth_status
            }
        )



