from django import forms
from django.contrib.auth.models import User
from .models import Customer, Transaction


class RegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'password']

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
            Customer.objects.create(user=user)
        return user


class TransferForm(forms.Form):
    receiver_id = forms.IntegerField(label="Receiver's Account Number")
    amount = forms.DecimalField(max_digits=10, decimal_places=2)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super().__init__(*args, **kwargs)

    def save(self):
        sender = Customer.objects.get(user=self.user)
        receiver = Customer.objects.get(
            account_number=self.cleaned_data['receiver_id'])
        amount = self.cleaned_data['amount']

        if sender.balance >= amount:
            sender.balance -= amount
            receiver.balance += amount
            sender.save()
            receiver.save()
            Transaction.objects.create(sender=sender, receiver=receiver,
                                       amount=amount)
        else:
            raise forms.ValidationError("Insufficient funds")
