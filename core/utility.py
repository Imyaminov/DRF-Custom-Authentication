import re
from rest_framework.validators import ValidationError

email_regex = re.compile(r"([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\"([]!#-[^-~ \t]|(\\[\t -~]))+\")@([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\[[\t -Z^-~]*])")
phone_regex = re.compile(r'^9\d{12}$')
username_regex = re.compile(r'^[a-zA-Z0-9_.-]+$')

def check_user_type(user_input):
    if re.fullmatch(email_regex, user_input):
        email_or_phone_or_username = 'email'
    elif re.fullmatch(phone_regex, user_input):
        email_or_phone_or_username = 'phone'
    elif re.fullmatch(username_regex, user_input):
        email_or_phone_or_username = 'username'
    else:
        data = {
            'success': False,
            'message': 'Email or Phone number is not valid!'
        }
        raise ValidationError(data)
    return email_or_phone_or_username
