import re
from rest_framework.validators import ValidationError

email_regex = re.compile(r"([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\"([]!#-[^-~ \t]|(\\[\t -~]))+\")@([-!#-'*+/-9=?A-Z^-~]+(\.[-!#-'*+/-9=?A-Z^-~]+)*|\[[\t -Z^-~]*])")
phone_regex = re.compile(r'^9\d{12}$')

def check_email_or_phone(email_or_phone):
    if re.fullmatch(email_regex, email_or_phone):
        email_or_phone = 'email'
    elif re.fullmatch(phone_regex, email_or_phone):
        email_or_phone = 'phone'
    else:
        data = {
            'success': False,
            'message': 'Email or Phone number is not valid!'
        }
        raise ValidationError(data)
    return email_or_phone