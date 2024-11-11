from django.contrib.auth.views import LogoutView
from django.urls import path
from .views import RegisterView, login_view, account_detail_view, \
    transfer_view, HomePageView, TwoFactorSetupView, verify_2fa_view, \
    verify_backup_code_view, GitHubWebhookView

urlpatterns = [
    path('', HomePageView.as_view(), name='home'),
    path('register/', RegisterView.as_view(), name='register'),
    path('webhook/github/', GitHubWebhookView.as_view(), name='github_webhook'),
    path('login/', login_view, name='login'),
    path('account/', account_detail_view, name='account_detail'),
    path('transfer/', transfer_view, name='transfer'),
    path('logout/', LogoutView.as_view(), name='logout'),
path('setup-2fa/', TwoFactorSetupView.as_view(), name='setup_2fa'),
path('verify_2fa/', verify_2fa_view, name='verify_2fa'),
    path('verify_backup_code/', verify_backup_code_view,
         name='verify_backup_code'),

]
