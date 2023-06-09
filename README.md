# DRF-Custom-Authentication API
API for authentication containing sign up with email and sms verification, login/logout and token refresh functionalities that is 
built with Django, Django Rest Api, Twilio SMS Api and HTML/CSS template.
This project contains seven api endpoints, which suits for 4 four page authorisation.

# How to use it
`post` Initial step - verification with email or phone number:
```
http://localhost:8000/user/signup/
```
Payloud should contain email or phonenumber in string format:
```
{
    "email_phone_number": "testuser@gmail.com"
}
```

`post` Second step - verify with code
```
http://localhost:8000/user/verify/
```
code and access token(bearer) from above response:
```
{
    "code": 7883
}
```
`patch` Third step - register user information after successfull verification
```
http://localhost:8000/user/change-user-info/
```
payload contaning below attributes and access token(bearer):
```
{
    "fistname": "jone",
    "username": "jone123",
    "bio": "some bio",
    "gender": "men",
    "password": "some password",
    "confirm_password": "some password" 
}
```
`post` Final step - login user:
```
http://localhost:8000/user/login/
```
payload contains `user_input` and `password` atttributes. user_input should is username:
```
{
    "user_input": "jone123",
    "password": "some password"
}
```

`post` Logout authenticated user
```
http://localhost:8000/user/logout/
```
Refresh token in payload, and access token(bearer) required.
```
{
    "refresh": "refresh token"
}
```
Success will be responsed if user is authenticated and refresh token is valid.

# Other endpoints
`get` Getting new verification code
```
http://localhost:8000/user/new-verify/
```
Only access token(bearer) is required 

`post` Refreshing the access token
```
http://localhost:8000/user/login-refresh/
```
Payload contains current access and refresh token. if tokens is blacklisted, it responses an error message.
```
{
    "access": "access token",
    "refresh": "refresh token"
}
```
Response contains new access token.











 
 

