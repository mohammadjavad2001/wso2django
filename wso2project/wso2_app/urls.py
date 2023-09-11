from django.urls import path
from . import views
# from .views import RegisterView,GetTokenView
urlpatterns = [
    
    path('register/', views.register),
    path('gettoken/', views.get_token),    
    path('getapis/', views.get_apis),
    path('createapi/', views.creatre_api),
    path('apirud/<str:apiId>/',views.API_RUD.as_view()),  
    path('apiswagger/<str:apiId>/swagger/',views.ApiSwagger.as_view()),    
      


    



]