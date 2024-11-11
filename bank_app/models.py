import random
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator
from django.db import models
from django_otp.plugins.otp_totp.models import TOTPDevice


def generate_account_number():
    while True:
        account_number = ''.join(
            [str(random.randint(0, 9)) for _ in range(10)])
        if not Customer.objects.filter(account_number=account_number).exists():
            return account_number


class Customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    balance = models.DecimalField(max_digits=10, decimal_places=2,
                                  default=0.00)
    account_number = models.CharField(max_length=10, unique=True,
                                      editable=False)
    is_2fa_set = models.BooleanField(default=False)
    totp_device = models.OneToOneField(TOTPDevice, on_delete=models.CASCADE,
                                       null=True, blank=True, editable=False)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    backup_codes = models.JSONField(default=list, blank=True)

    def save(self, *args, **kwargs):
        if not self.account_number:
            self.account_number = generate_account_number()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.username} - Account Number: {self.account_number} - Balance: {self.balance}"


class Transaction(models.Model):
    sender = models.ForeignKey(Customer, on_delete=models.CASCADE,
                               related_name='sent_transactions')
    receiver = models.ForeignKey(Customer, on_delete=models.CASCADE,
                                 related_name='received_transactions')
    amount = models.DecimalField(max_digits=10, decimal_places=2,
                                 validators=[MinValueValidator(0.01)])
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.sender.user.username} -> {self.receiver.user.username}: ${self.amount}"
