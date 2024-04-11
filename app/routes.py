from flask import render_template, redirect, url_for, request, flash
from flask_login import current_user, login_user, logout_user, login_required
from app import app, db, login_manager
from app.models import User
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
from flask_mail import Mail, Message

# Настройки SMTP сервера
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'rusokoro2002@gmail.com'  # Ваш логин для SMTP
app.config['MAIL_PASSWORD'] = 'ypur ojln ksci xzfv'  # Ваш пароль для SMTP

mail = Mail(app)

login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/profile')
@login_required
def profile():
    # Этот код будет выполнен только для аутентифицированных пользователей
    return render_template('profile.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from sqlalchemy import or_

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Если пользователь уже аутентифицирован, перенаправляем его на страницу профиля
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    # Остальной код функции остается без изменений
    if request.method == 'POST':
        username_or_email = request.form['username_or_email']
        password = request.form['password']
        remember = request.form.get('remember')  # Проверяем, установлен ли флажок "запомнить меня"

        # Проверяем, является ли введенная строка email'ом
        if '@' in username_or_email:
            user = User.query.filter_by(email=username_or_email).first()
        else:
            user = User.query.filter_by(username=username_or_email).first()

        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)  # Указываем параметр remember
            return redirect(url_for('profile'))  # Перенаправляем пользователя после успешной авторизации
        else:
            flash('Неверный email или пароль', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    # Если пользователь уже аутентифицирован, перенаправляем его на страницу профиля
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    # Остальной код функции остается без изменений
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        # Проверяем, что пользователь с таким email уже не существует
        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже зарегистрирован!', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем пользователя уже зарегистрирован!', 'error')
            return redirect(url_for('register'))
        # Создаем нового пользователя
        new_user = User(username=username, email=email, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        # Авторизуем пользователя
        login_user(new_user)
        flash('Регистрация прошла успешно!', 'success')
        return redirect(url_for('profile'))
    return render_template('register.html')


@app.route('/terms-of-use')
def termsOfUse():
    return render_template('terms-of-use.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/contacts')
def contacts():
    return render_template('contacts.html')

@app.route('/users')
def users():
    all_users = User.query.all()
    return render_template('users.html', users=all_users)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из учетной записи.', 'success')
    return redirect(url_for('login'))

@app.route('/reset-password-successfully', methods=['GET', 'POST'])
def reset_password_successfully():
    return render_template('reset-password-successfully.html')

@app.route('/reset-password-request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(20)
            user.reset_token = token
            user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)  # Срок действия токена - 1 час
            db.session.commit()
            send_password_reset_email(user)
            flash('Проверьте вашу электронную почту для инструкций по сбросу пароля', 'info')
            return redirect(url_for('login'))
        else:
            flash('Пользователь с таким email не найден', 'error')
    return render_template('reset-password-request.html')

def send_password_reset_email(user):
    print("Отправка письма для сброса пароля...")
    token = user.reset_token
    msg = Message('Сброс пароля', sender='noreply@example.com', recipients=[user.email])
    msg.body = f'''
    Чтобы сбросить пароль, посетите следующую ссылку:
    {url_for('reset_password', token=token, _external=True)}
    Если вы не запрашивали сброс пароля, проигнорируйте это сообщение.
    '''
    print("Сообщение сформировано. Попытка отправки письма...")
    try:
        mail.send(msg)
        print("Письмо успешно отправлено.")
    except Exception as e:
        print("Ошибка при отправке письма:", e)

    print("Функция send_password_reset_email выполнена.")


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if user and user.reset_token_expiration > datetime.utcnow():
        if request.method == 'POST':
            password = request.form['password']
            user.password = generate_password_hash(password)
            user.reset_token = None
            user.reset_token_expiration = None
            db.session.commit()
            flash('Пароль успешно изменен', 'success')
            return redirect(url_for('login'))
        return render_template('reset-password.html', token=token)
    else:
        flash('Недействительный или просроченный токен сброса пароля', 'error')
        return redirect(url_for('reset-password-request'))

# def delete_user_by_username(username):
#     with app.app_context():
#         user = User.query.filter_by(username=username).first()
#         if user:
#             db.session.delete(user)
#             db.session.commit()
#             print(f"Пользователь с именем {username} успешно удален.")
#         else:
#             print(f"Пользователь с именем {username} не найден.")
#
# # Пример вызова функции для удаления пользователя по имени
# delete_user_by_username('asdasdasd')