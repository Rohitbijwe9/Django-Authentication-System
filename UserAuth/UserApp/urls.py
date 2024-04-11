from django.urls import path,include
from .views import UserRegistration ,LoginView,PasswordResetView,PasswordResetConfirmView
from rest_framework.routers import SimpleRouter

router=SimpleRouter()




router.register('userreg',UserRegistration,basename='userreg'),


urlpatterns = [
    path('register/',include(router.urls)),
    path('verify-otp/', UserRegistration.as_view({'post': 'check_otp'})),
    path('login/',LoginView.as_view()),
    path('reset-pass/',PasswordResetView.as_view()),
    path('password/reset/confirm/<str:uidb64>/<str:token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),

    

]
