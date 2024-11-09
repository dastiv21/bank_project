from django.contrib import messages
from django.shortcuts import render

# Create your views here.
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views import View

from .models import Customer, Transaction
from .forms import TransferForm, RegistrationForm


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

            return redirect('home')
        return render(request, 'bank_app/register.html', {'form': form})


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('account_detail')
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
