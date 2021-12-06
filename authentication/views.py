from django.shortcuts import redirect, render
from django.contrib.auth.models import User, auth
from django.contrib import messages
from .models import *
import uuid
import re
from django.conf import settings
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.decorators import login_required
from .helpers import send_forgot_password_mail
# Create your views here.

@login_required(login_url='login')
def home(request):
    return render(request, 'home.html')

@login_required(login_url='login')
def ViewProfile(request):
    return render(request,'profile.html')

def login_attempt(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user_obj = User.objects.filter(username=username).first()

        if user_obj is None:
            messages.info(request,'Username not found.')
            return redirect('/login')

        profile_obj = Profile.objects.filter(user=user_obj).first()  

        if not profile_obj.is_verified:
            messages.info(request,'Profile is not verified, check your mail.')
            return redirect('/login')
        user = authenticate(username=username, password=password) 
        if user is None:
            messages.info(request,'Wrong password, You are entered.')
            return redirect('/login')
        login(request,user)
        return redirect('/')       

    return render(request, 'login.html')

def register_attempt(request):    
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')        
        confirm_password = request.POST.get('confirmpassword')

        flag = 0
        if (len(password)<7 or len(password)>15):
            flag = 1
        elif not re.search('[a-z]', password):
            flag = 1
        elif not re.search('[0-9]', password):
            flag = 1
        elif not re.search('[A-Z]', password):
            flag = 1
        elif not re.search('[@#$!]', password):
            flag = 1  
            
        if (flag == 0):
            if password==confirm_password:            
                try:
                    if User.objects.filter(username=username).first():
                        messages.info(request,'Username is taken')
                        return redirect('/register')
                    if User.objects.filter(email=email).first():
                        messages.info(request,'Email is taken')
                        return redirect('/register')  
                    user_obj = User(username=username, email=email)   
                    user_obj.set_password(password) 
                    user_obj.save() 
                    auth_token=str(uuid.uuid4())
                    profile_obj = Profile.objects.create(user=user_obj, auth_token=auth_token)
                    profile_obj.save()
                    send_mail_after_registrtion(email, auth_token)
                    messages.success(request,'An email is sent, Please verify your mail...')
                    return redirect('/register') 
                    
                except Exception as e:
                    print(e)

    return render(request, 'register.html',{})  

@login_required(login_url='login')    
def Logout(request):
    auth.logout(request) 
    return redirect('login') 


def success(request):
    return render(request, 'success.html')


def verify(request, auth_token):
    try:
        profile_obj = Profile.objects.filter(auth_token=auth_token).first()
        if profile_obj:
            if profile_obj.is_verified:
                messages.success(request, "Your account has already verified.")
                return redirect('/login')

            profile_obj.is_verified=True
            profile_obj.save()
            messages.success(request, "Your account has been verified, You can Login.")
            return redirect('/login')
        else:
            return redirect('/error')
    except Exception as e:
            print(e)       


def error_page(request):
    return render(request, 'error.html')    


def send_mail_after_registrtion(email, token):
    subject = 'Your account need to verified'
    message = f'Hi paste the link to verify your account http://127.0.0.1:8000/verify/{token}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)

   
def ForgetPassword(request):
    try:        
        if request.method == 'POST':
            username = request.POST.get('username')
            if not User.objects.filter(username=username).first():
                messages.success(request,'Not user found with this username')
                return redirect('/forget-password/') 

            user_obj = User.objects.get(username=username)  
            token = str(uuid.uuid4())
            profile_obj = Profile.objects.get(user=user_obj)
            profile_obj.auth_token = token
            profile_obj.save()
            send_forgot_password_mail(user_obj.email, token)
            messages.success(request,'An email is sent...')
            return redirect('/forget-password/') 

    except Exception as e:
        print(e)  
    return render(request,'forget_password.html')      


def ResetPassword(request, token):
    context = {}
    try:        
        profile_obj = Profile.objects.filter(auth_token=token).first()
        context = {'user_id':profile_obj.user.id}
        print(profile_obj)

        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            reconfirm_password = request.POST.get('reconfirm_password')
            user_id = request.POST.get('user_id')

            if user_id is None:
                messages.success(request,'No user id found')
                return redirect(f'/reset-password/{token}/')

            if new_password != reconfirm_password:
                messages.success(request,'both password need equal')
                return redirect(f'/reset-password/{token}/')

            user_obj = User.objects.get(id=user_id)
            user_obj.set_password(new_password)
            user_obj.save()
            messages.success(request,'New Password create successfully.')
            return redirect('/login')       

    except Exception as e:
        print(e)  
    
    return render(request,'reset_password.html',context)  


@login_required(login_url='login')
def Update_password(request):
    context={}
    if request.method == 'POST':
        current = request.POST['cpwd']
        new_password = request.POST['npwd']
        confirm_password = request.POST['cppwd']
        
        user = User.objects.get(id=request.user.id)
        username = user.username
        check = user.check_password(current)
        if check==True:
            if new_password==confirm_password:
                user.set_password(new_password)
                user.save()

                context["msz"]="Password changed successfully."
                context["col"]="alert-success"
                user = User.objects.get(username=username)
                login(request,user)
                return redirect('/')
            else:
                context["msz"]="New Password and Confirm Password must be equal.."
                context["col"]="alert-danger"

        else:
            context["msz"]="Incorrect Current Password"
            context["col"]="alert-danger"
          
        print(check)
        
    return render(request,'update_password.html',context)


