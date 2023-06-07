from django.contrib.auth.password_validation import validate_password
from django.db.models import Q
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from core.utility import check_email_or_phone
from shared.utils import phone_parser, send_email, send_phone_notification
from .models import CustomUser, VIA_EMAIL, VIA_PHONE, CODE_VERIFIED, DONE, NEW


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

    def validate_email_phone_number(self, value):
        value = value.lower()

        query = (
            (Q(phone_number=value) | Q(email=value)) &
            (Q(auth_status=CODE_VERIFIED) | Q(auth_status=NEW))
        )
        if CustomUser.objects.filter(query).exists():
            CustomUser.objects.get(query).delete()

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

class ChangeUserInformationSerializer(serializers.Serializer):
    bio = serializers.CharField(write_only=True, required=True)
    gender = serializers.CharField(write_only=True, required=True)
    first_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate_bio(self, bio):
        if bio  and len(bio)>250:
            raise ValidationError('Bio must be between 0 to 250 characters long')
        return bio

    def validate_password(self, password):
        validate_password(password)
        return password

    def validate_username(self, username):
        user_username = self.context['request'].user.username
        if len(username) < 5 or len(username) > 30:
            raise ValidationError('Username must be between 5 to  30  characters long')
        if username.isdigit():
            raise ValidationError('This username is entirely numeric')
        if CustomUser.objects.filter(username__iexact=username).exclude(username=user_username).exists():
            raise ValidationError('This username already exists!')
        return username

    def validate(self, data):
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        if password:
            validate_password(password)
            validate_password(confirm_password)
        if password != confirm_password:
            raise ValidationError("Passwords did not match!")
        return data

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get("first_name", instance.first_name)
        instance.username = validated_data.get("username", instance.username)
        instance.password = validated_data.get("password", instance.password)
        instance.gender = validated_data.get("gender", instance.gender)
        instance.bio = validated_data.get("bio", instance.bio)

        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))
        if instance.auth_status == CODE_VERIFIED:
            user = self.context['request'].user
            user.auth_status = DONE
            user.save()

        instance.save()
        return instance






