from django.contrib import admin
from .models import CustomUser, UserComfirmation

# Register your models here.

class CustomUserModel(admin.ModelAdmin):
    list_display = (
        'id',
    )
admin.site.register(CustomUser, CustomUserModel)

class UserConfirmationModel(admin.ModelAdmin):
    list_display = (
        'id',
    )
admin.site.register(UserComfirmation, UserConfirmationModel)
