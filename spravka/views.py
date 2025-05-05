from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

def glavnaya(request):
    return render(request, 'index.html')

def signupuser(request):
    if request.method == 'GET':
        return render(request, 'signupuser.html', {'form': UserCreationForm()})
    else:
        if request.POST['password1'] == request.POST['password2']:
            form = UserCreationForm(request.POST)
            if form.is_valid():
                user = form.save()
                return redirect('glavnaya')  # Перенаправление на главную страницу
            else:
                # Обработка ошибок формы
                return render(request, 'signupuser.html', {'form': form})
        else:
            print('Passwords did not match')
            return render(request, 'signupuser.html', {'form': UserCreationForm(), 'error': 'Пароли не совпадают'})  # Добавление сообщения об ошибке