import random
import uuid
from datetime import datetime, timedelta
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.contrib.auth.models import UserManager
from rest_framework_simplejwt.tokens import RefreshToken
from shared.models import BaseModel

ORDINARY_USER, MANAGER, SUPER_ADMIN = (
    'ordinary_user',
    'manager',
    'super_admin',
)
VIA_EMAIL, VIA_PHONE, VIA_USERNAME = (
    'via_email',
    'via_phone',
    'via_username',
)
MAIL, FEMAIL = (
    'mail',
    'femail'
)
NEW, CODE_VERIFIED, INFORMATION_FILLED, DONE = (
    'new',
    'code_verified',
    'information_filled',
    'done',
)

PHONE_EXPIRE, EMAIL_EXPIRE = (2, 5)

class UserComfirmation(models.Model):
    TYPE_CHOICES = (
        (VIA_EMAIL, VIA_EMAIL),
        (VIA_PHONE, VIA_PHONE)
    )
    code = models.CharField(max_length=4)
    user = models.ForeignKey('user.CustomUser', on_delete=models.SET_NULL, related_name='verify_codes', null=True)
    verify_type = models.CharField(max_length=128, choices=TYPE_CHOICES)
    expiration_time = models.DateTimeField(null=True)
    is_confirmed = models.BooleanField(default=False)

    def __str__(self):
        return str(self.user.__str__())

    def save(self, *args, **kwargs):
        if not self.pk:
            if self.verify_type == VIA_EMAIL:
                self.expiration_time = datetime.now() + timedelta(minutes=EMAIL_EXPIRE)
            else:
                self.expiration_time = datetime.now() + timedelta(minutes=PHONE_EXPIRE)
        super(UserComfirmation, self).save(*args, **kwargs)


class CustomUser(AbstractUser, BaseModel):
    _validate_phone = RegexValidator(
        regex=r"^9\d{12}$",
        message='Phone number must start from 9 and contain 12 characters. For example: 998998065999'
    )
    USER_ROLES = (
        (ORDINARY_USER, ORDINARY_USER),
        (MANAGER, MANAGER),
        (SUPER_ADMIN, SUPER_ADMIN),
    )
    AUTH_TYPE_CHOICES = (
        (VIA_EMAIL, VIA_EMAIL),
        (VIA_PHONE, VIA_PHONE),
        (VIA_USERNAME, VIA_USERNAME),
    )
    AUTH_STATUS = (
        (NEW, NEW),
        (CODE_VERIFIED, CODE_VERIFIED),
        (INFORMATION_FILLED, INFORMATION_FILLED),
        (DONE, DONE),
    )
    GENDER = (
        (MAIL, MAIL),
        (FEMAIL, FEMAIL)
    )
    user_roles = models.CharField(max_length=128, choices=USER_ROLES, default=ORDINARY_USER)
    auth_type = models.CharField(max_length=128, choices=AUTH_TYPE_CHOICES, default=VIA_USERNAME)
    auth_status = models.CharField(max_length=128, choices=AUTH_STATUS, default=NEW)
    gender = models.CharField(max_length=128, choices=GENDER, null=True)
    email = models.EmailField(null=True, unique=True)
    phone_number = models.CharField(max_length=12, null=True, unique=True, validators=[_validate_phone])
    bio = models.CharField(max_length=256, null=True)

    objects = UserManager()

    def __str__(self):
        return self.username

    @property
    def get_full_name(self):
        return '{} {}'.format(self.first_name, self.last_name)

    def create_verify_code(self, verify_type):
        code = ''.join([str(random.randint(0, 100) % 10) for _ in range(4)])
        UserComfirmation.objects.create(
            user_id=self.id,
            code=code,
            verify_type=verify_type,
        )
        return code

    def check_username(self):
        if not self.username:
            temp = f'DemoProject-{uuid.uuid4().__str__().split("-")[-1]}'
            while CustomUser.objects.filter(username=temp):
                temp = f'{temp}{random.randint(0,9)}'
            self.username = temp

    def check_email(self):
        if self.email:
            normalized = self.email.lower()
            self.email = normalized

    def check_pass(self):
        if not self.password:
            temp = f'password-{uuid.uuid4().__str__().split("-")[-1]}'
            self.password = temp

    def hashing_password(self):
        if not self.password.startswith('pbkdf2_sha256'):
            self.set_password(self.password)

    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }

    def save(self, *args, **kwargs):
        if not self.pk:
            self.clean()
        super(CustomUser, self).save(*args, **kwargs)

    def clean(self):
        self.check_email()
        self.check_username()
        self.check_pass()
        self.hashing_password()












