from django.urls import path
from .import views

urlpatterns = [
    path('', views.home, name="home"),
    path('login', views.login_attempt, name='login'),
    path('register', views.register_attempt, name='register'),
    path('logout', views.Logout, name='logout'),    
    path('verify/<slug:auth_token>', views.verify, name='verify'),   

    path('forget-password/', views.ForgetPassword, name='forget-password'),    
    path('reset-password/<token>/', views.ResetPassword, name='reset-password'),
    path('update_password/', views.Update_password, name='update_password'),
    
    path('success', views.success, name='success'),
    path('error', views.error_page, name='error'),
    path('profile', views.ViewProfile, name='viewprofie'),


    
]
