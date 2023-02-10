from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from rest_framework.exceptions import ValidationError
from twilio.rest import Client
import phonenumbers as phonenumbers
import threading


class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self) -> None:
        self.email.send()


class Email:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            to=[data['to_email']]
        )
        if data.get('content_type') == 'html':
            email.content_subtype = 'html'
        EmailThread(email).start()


def send_email(email, code):
    html_content = render_to_string(
        'email/authentication/activate_account.html',
        {'code': code}
    )
    Email.send_email({
        'subject': 'Registration',
        'body': html_content,
        'to_email': email,
        'content_type': 'html'
    })

def send_phone_notification(phone, code):
    account_sid = config('account_sid')
    auth_token = config('auth_token')
    client = Client(account_sid, auth_token)
    client.messages.create(
        body=f'Hello, Your verification code is {code}\n',
        from_='+43948328492', # number given from twilio after registration(admin),
        to=f'{phone}',
    )


def phone_checker(phone_number):
    if not(phone_number and isinstance(phone_number, str) and phone_number.isdigit()):
        raise ValidationError('Phone number is not valid!')

def phone_parser(phone_number, c_code=None):
    try:
        phone_checker(phone_number)
        phone_number = '+' + phone_number
        return phonenumbers.parse(phone_number, c_code)
    except Exception as e:
        raise ValidationError('Phone number is not valid!')



