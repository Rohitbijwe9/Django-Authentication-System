from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializer import UserSerializer,PasswordResetRequestSerializer,PasswordResetSerializer
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from django.core.mail import send_mail
from . models import User
from django.contrib.auth import authenticate

from django.utils.http import urlsafe_base64_decode
from rest_framework_simplejwt.exceptions import TokenError
import logging
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import generics


from rest_framework import generics
from rest_framework import serializers


from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken



from rest_framework import viewsets
from django.contrib.auth import get_user_model


from rest_framework import status, generics
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model
from rest_framework.response import Response


import random
otpn = random.randint(1000, 9999)  # Generate OTP



otp = random.randint(1000, 9999)  # Generate OTP

User = get_user_model()

class UserRegistration(viewsets.ViewSet):
    def create(self, request):
        serializer = UserSerializer(data=request.data)
      
        if serializer.is_valid():
            email = serializer.validated_data['email']
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            otp = random.randint(1000, 9999)

            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                is_active=False
            )

            user.set_password(password)
            user.save()

            request.session['user_id'] = user.id
            request.session['otp'] = otp

            subject = 'OTP Verification'
            message = f'Your OTP is: {otp}'
            print(otp)
            from_email = settings.EMAIL_HOST_USER
            to_email = [email]
            request.session['otp'] = otp
            request.session['email'] = email

            try:
                send_mail(subject, message, from_email, to_email)
                return Response({'message': 'User created successfully. OTP sent for verification.'}, status=status.HTTP_201_CREATED)
            except Exception as e:
                user.delete()
                return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 

    def check_otp(self, request):
        otp_from_user = request.data.get('otp')
        otp = request.session.get('otp')
        email = request.session.get('email')

        print('otp', otp)
        print('uotp', otp_from_user)
        print('email', email)

        if not email:
            return Response({'error': 'Email not provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)

        if otp_from_user and otp:
            if int(otp_from_user) == otp:
                user.is_active = True
                user.save()
                del request.session['otp']
                return Response({'message': 'OTP verified successfully. Account activated.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'OTP not found or missing data'}, status=status.HTTP_400_BAD_REQUEST)






class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        if user:
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            return Response({
                'refresh': str(refresh),
                'access': str(access_token),
            })
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)





class PasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        User = get_user_model()
        user = User.objects.filter(email=email).first()
        if user:
            token = default_token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            reset_link = request.build_absolute_uri(reset_url)

            email_message = EmailMessage(
                'Password Reset Request',
                f'Use the link below to reset your password: {reset_link}',
                to=[email],
            )
            email_message.send()

        return Response({'detail': 'Password reset email sent'}, status=status.HTTP_200_OK)



class PasswordResetSerializer(serializers.Serializer):
    new_password = serializers.CharField()

class PasswordResetConfirmView(generics.GenericAPIView):
    """
    Confirm password reset and set new password.
    """
    
    serializer_class = PasswordResetSerializer
    
    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'error': 'Invalid user ID'}, status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, token):
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                new_password = serializer.validated_data['new_password']
                user.set_password(new_password)
                user.save()
                return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)
