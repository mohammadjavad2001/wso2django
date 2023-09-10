from django.urls import path
from . import views
# from .views import RegisterView,GetTokenView
urlpatterns = [
    
    path('register/', views.register),
    path('gettoken/', views.get_token),


    



]