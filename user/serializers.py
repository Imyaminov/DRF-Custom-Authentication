from pprint import pprint

from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from core.utility import check_email_or_phone
from shared.utils import phone_parser, send_email, send_phone_notification
from .models import CustomUser, VIA_EMAIL, VIA_PHONE


class SignUpSerializer(serializers.ModelSerializer):
    guid = serializers.UUIDField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = CustomUser
        fields = (
            'guid',
            'auth_type',
            'auth_status',
        )
        extra_kwargs = {
            'auth_type': {'read_only': True, 'required': False},
            'auth_status': {'read_only': True, 'required': False},
        }

    def create(self, validated_data):
        user = super(SignUpSerializer, self).create(validated_data)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(user.auth_type)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(user.auth_type)
            # send_phone_notification(user.phone_number, code)
            send_email(user.email, code) # just for now since i don't have twilio account yet
        user.save()
        return user


    def validate(self, attrs):
        super(SignUpSerializer, self).validate(attrs)
        data = self.auth_validate(attrs)
        return data

    @staticmethod
    def auth_validate(attrs):
        user_input = str(attrs.get('email_phone_number')).lower()
        input_type = check_email_or_phone(user_input)
        if input_type == 'email':
            data = {
                'email': attrs.get('email_phone_number'),
                'auth_type': VIA_EMAIL
            }
        elif input_type == 'phone':
            data = {
                'phone': attrs.get('email_phone_number'),
                'auth_type': VIA_PHONE
            }
        elif input_type is None:
            data = {
                'success': False,
                'message': 'You must send Email or Phone number'
            }
            raise ValidationError(data)
        else:
            data = {
                'success': False,
                'message': 'Must enter Email or Phone number'
            }
        return data

    def validate_email_or_phone_number(self, value):
        value = value.lower()

        # value = 'imyaminov2505@gmail.com'
        # value = '998065999'
        # value = '90dasdas@fsdfsd...'

        if value and CustomUser.objects.all().filter(email=value).exists():
            data = {
                'success': False,
                'message': 'This email is already registered!'
            }
            raise ValidationError(data)
        elif value and CustomUser.objects.all().filter(phone_number=value).exists():
            data = {
                'success': False,
                'message': 'This phone number is already registered!'
            }
            raise ValidationError(data)
        if check_email_or_phone(value) == 'phone':
            phone_parser(value, self.initial_data.get('country_code'))
        return value

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())
        # create token() method then define it(understand)
        # pprint(data)
        return data

class ChangeUserInformation(serializers.Serializer):
    bio = serializers.CharField()


    def validate_password(self, password):
        validate_password(password)
        return password

    def validate_username(self, username):
        requested_user = self.context['request'].user
        user_username = requested_user.username
        if len(username) < 5 or len(username) > 30:
            raise ValidationError('Username > 5 and < 30')
        if username.isdigit():
            raise ValidationError('This username is entirely numeric')
        if CustomUser.objects.fitler(username__iexact=username).exclude(username=user_username):
            raise ValidationError('Username is already exists!')
        return username








