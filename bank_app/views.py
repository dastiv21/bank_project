import hashlib
import hmac

from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views import View
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Customer, Transaction
from .forms import TransferForm, RegistrationForm
import qrcode
import base64
from io import BytesIO
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.views import View
from django.shortcuts import render, redirect
from django.contrib import messages

from .utls import generate_backup_codes


class HomePageView(View):
    def get(self, request):
        return render(request, 'bank_app/home.html')


class RegisterView(View):
    def get(self, request):
        form = RegistrationForm()
        return render(request, 'bank_app/register.html', {'form': form})

    def post(self, request):
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()

            # Generate a unique 10-digit account number
            # account_number = self.generate_unique_account_number()

            # Create the Customer instance
            Customer.objects.create(user=user)

            # Log in the user and redirect to home

            login(request, user)
            messages.success(request,
                             'Registration successful! Welcome to Bank App.')

            # return redirect('home')
            return redirect('setup_2fa')
        return render(request, 'bank_app/register.html', {'form': form})


# def login_view(request):
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             login(request, user)
#             return redirect('account_detail')
#     return render(request, 'bank_app/login.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # Check if 2FA is set up for the user
            if user.customer.is_2fa_set:
                # Redirect to 2FA verification page
                return redirect('verify_2fa')
            else:
                # Log the user in if 2FA is not set up
                login(request, user)
                return redirect('account_detail')
        else:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'bank_app/login.html')

@login_required
def account_detail_view(request):
    customer = Customer.objects.get(user=request.user)
    return render(request, 'bank_app/account_detail.html',
                  {'customer': customer})


@login_required
def transfer_view(request):
    if request.method == 'POST':
        form = TransferForm(request.POST, user=request.user)
        if form.is_valid():
            form.save()
            messages.success(request,
                             'Transfer Operation completed')

            return redirect('account_detail')

    else:
        form = TransferForm(user=request.user)
    return render(request, 'bank_app/transfer.html', {'form': form})


class TwoFactorSetupView(View):
    def get(self, request):
        user = request.user
        if not user.is_authenticated:
            return redirect('login')

        # Check if the user already has a TOTP device
        if user.totpdevice_set.exists():
            return redirect('account_detail')

        # Create a new TOTP device for the user
        device = TOTPDevice.objects.create(user=user, name='default')

        # Generate the QR code URL
        qr_code_url = device.config_url

        # Generate the QR code image
        qr = qrcode.make(qr_code_url)
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()

        return render(request, 'bank_app/setup_2fa.html', {
            'qr_code_base64': qr_code_base64,
            'verification_required': True  # Flag to show the OTP form
        })

    def post(self, request):
        user = request.user
        otp = request.POST.get("otp")

        # Retrieve the user's TOTP device
        device = TOTPDevice.objects.filter(user=user, name='default').first()

        if device and device.verify_token(otp):
            # OTP is correct; activate the device
            device.confirmed = True
            device.save()
            customer = user.customer
            customer.is_2fa_set = True
            customer.save()

            backup_codes = generate_backup_codes()
            request.user.customer.backup_codes = backup_codes
            request.user.customer.save()
            messages.success(request,
                             "Two-factor authentication setup complete.")
            return redirect('account_detail')
        else:
            # OTP is incorrect
            messages.error(request, "Invalid OTP. Please try again.")
            return redirect('setup_2fa')

@login_required
def verify_2fa_view(request):
    if request.method == 'POST':
        token = request.POST.get('token')
        device = request.user.totpdevice_set.first()

        if device and device.verify_token(token):
            # Token is correct; log the user in
            login(request, request.user)
            messages.success(request, 'Two-factor authentication successful.')
            return redirect('home')
        else:
            # Token is incorrect
            messages.error(request, 'Invalid token. Please try again.')
            return redirect('verify_2fa')
    return render(request, 'bank_app/verify_2fa.html')

@login_required
def verify_backup_code_view(request):
    if request.method == 'POST':
        code = request.POST.get('code')
        print(code)
        print(request.user.customer.backup_codes)
        if code in request.user.customer.backup_codes:
            # Mark the code as used and save
            request.user.customer.backup_codes.remove(code)
            request.user.customer.save()
            login(request, request.user)
            messages.success(request, 'Backup code verified.')
            return redirect('home')
        else:
            messages.error(request, 'Invalid backup code.')
            return redirect('verify_backup_code')

    return render(request, 'bank_app/verify_backup_code.html')


import hmac
import hashlib
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
import json

class GitHubWebhookView(APIView):
    """
    Webhook endpoint to handle GitHub push events for file updates.
    """

    def post(self, request, *args, **kwargs):
        # Secret token for validation
        print("here")
        secret_token = settings.GITHUB_WEBHOOK_SECRET.encode()

        # Validate secret token
        signature = request.headers.get('X-Hub-Signature-256')
        if not signature or not self.is_valid_signature(request.body, signature, secret_token):
            return Response({"error": "Invalid secret token"},
                            status=status.HTTP_403_FORBIDDEN)

        # Parse the payload
        print(request.body)
        try:
            payload = json.loads(request.body)
        except json.JSONDecodeError:
            return Response({"error": "Invalid JSON payload"},
                            status=status.HTTP_400_BAD_REQUEST)

        # Only process push events
        if payload.get("event") != "push":
            return Response({"error": "Unsupported event type"},
                            status=status.HTTP_400_BAD_REQUEST)

        # Process the file updates (additional logic would go here)
        file_updates = []  # Placeholder for processing files

        # Success response
        return Response({"message": "Push event processed successfully", "files": file_updates},
                        status=status.HTTP_200_OK)

    @staticmethod
    def is_valid_signature(payload, signature, secret):
        # Compute HMAC hex digest using sha256
        hash_hex = hmac.new(secret, payload, hashlib.sha256).hexdigest()
        # Compare with the GitHub signature
        return hmac.compare_digest(f'sha256={hash_hex}', signature)


def save_audit_log(data, event_type):
    print(data)
    return {"status": "success", "event_type": event_type, "data": data}
