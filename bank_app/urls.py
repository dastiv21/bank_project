from django.contrib.auth.views import LogoutView
from django.urls import path
from .views import RegisterView, login_view, account_detail_view, \
    transfer_view, HomePageView

urlpatterns = [
    path('', HomePageView.as_view(), name='home'),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', login_view, name='login'),
    path('account/', account_detail_view, name='account_detail'),
    path('transfer/', transfer_view, name='transfer'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
