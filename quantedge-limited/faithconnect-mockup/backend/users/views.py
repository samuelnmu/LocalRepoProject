from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from .models import OTP
from datetime import timedelta
import random

User = get_user_model()


# Register new user
class RegisterUserAPIView(APIView):
    def post(self, request):
        email = request.data.get("email")
        first_name = request.data.get("first_name")
        last_name = request.data.get("last_name")
        phone_number = request.data.get("phone_number")

        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({"error": "User already exists"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
        )
        return Response({"message": "User created successfully", "user_id": user.id}, status=status.HTTP_201_CREATED)


# Request OTP
class RequestOTPAPIView(APIView):
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Prevent frequent OTP requests (1 per minute)
        recent_otp = OTP.objects.filter(user=user).order_by('-created_at').first()
        if recent_otp and (timezone.now() - recent_otp.created_at) < timedelta(minutes=1):
            return Response({"error": "Wait 1 minute before requesting a new OTP"}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        # Generate 6-digit OTP
        raw_otp = str(random.randint(100000, 999999))
        OTP.objects.create(user=user, code=make_password(raw_otp))

        # In production, send via email/SMS instead of returning
        return Response({"otp": raw_otp, "message": "OTP generated"}, status=status.HTTP_200_OK)


# Verify OTP (login)
class VerifyOTPAPIView(APIView):
    def post(self, request):
        email = request.data.get("email")
        otp_code = request.data.get("otp")

        if not email or not otp_code:
            return Response({"error": "Email and OTP are required"}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, email=email, otp_code=otp_code)
        if user:
            return Response({"message": "OTP verified. User logged in!"}, status=status.HTTP_200_OK)

        return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
