from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    
    password=serializers.CharField(write_only=True,min_length=6)
     

    class Meta:
        model=User
        fields=('first_name','last_name','email','username','password')


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8)
    token = serializers.CharField()
    uidb64 = serializers.CharField()