from flask import render_template, redirect, url_for, request, flash
from flask_login import current_user, login_user, logout_user, login_required
from app import app, db, login_manager
from app.models import User
from app.models import Password
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
from flask_mail import Mail, Message
from flask import jsonify
from validate_email import validate_email
import os
from werkzeug.utils import secure_filename
import uuid
import transliterate
from slugify import slugify

@app.template_filter('slugify')
def custom_slugify(s):
    return slugify(s)

# Настройки SMTP сервера
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'rusokoro2002@gmail.com'  # Ваш логин для SMTP
app.config['MAIL_PASSWORD'] = 'ypur ojln ksci xzfv'  # Ваш пароль для SMTP

mail = Mail(app)

login_manager.init_app(app)

# Роутинг по сайту:
# ===============================================================

# 404 (/404)
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404
#----------------------------------------------------------------

# Помощь (/help)
@app.route('/help')
def help():
    return render_template('help.html')
#----------------------------------------------------------------

# Пользовательское соглашение (/terms-of-use)
@app.route('/terms-of-use')
def termsOfUse():
    return render_template('terms-of-use.html')
#----------------------------------------------------------------

# Домашняя страница (/)
@app.route('/')
def home():
    return render_template('home.html')
#----------------------------------------------------------------

# Контакты (/contacts)
@app.route('/contacts')
def contacts():
    return render_template('contacts.html')
#----------------------------------------------------------------

# Пользователи (/users)
@app.route('/users')
def users():
    all_users = User.query.all()
    return render_template('users.html', users=all_users)
#----------------------------------------------------------------

# Пользователи (/users)
@app.route('/passwords')
def passwords():
    all_passwords = Password.query.all()
    return render_template('passwords.html', passwords=all_passwords)
#----------------------------------------------------------------

#================================================================


# Роутинг по приложению:
# ===============================================================

# Главная страница приложжения (/profile)
@app.route('/profile')
@login_required
def profile():
    username = current_user.username
    email = current_user.email
    passwords = Password.query.filter_by(user_id=current_user.id).all()
    categories = Password.query.with_entities(Password.category).filter_by(user_id=current_user.id).distinct().all()
    password_id = request.args.get('password_id')  # Получаем password_id из запроса
    return render_template('profile.html', username=username, email=email, passwords=passwords, categories=categories, password_id=password_id)

#----------------------------------------------------------------
from uuid import uuid4

@app.route('/add_password', methods=['POST'])
@login_required
def add_password():
    if request.method == 'POST':
        # Получаем файл изображения из формы
        if 'image' in request.files and request.files['image'].filename != '':
            image = request.files['image']

            # Получаем путь к папке пользователя
            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)

            # Создаем папку пользователя, если она не существует
            if not os.path.exists(user_folder):
                os.makedirs(user_folder)

            # Генерируем уникальное имя файла
            filename = str(uuid4()) + secure_filename(image.filename)

            # Сохраняем изображение на сервере
            image.save(os.path.join(user_folder, filename))

            # Сохраняем путь к изображению в базе данных
            image_path = os.path.join('uploads', current_user.username, filename)
        else:
            image_path = ''

        new_password = Password(
            title=request.form['title'],
            category=request.form['category'],
            description=request.form['description'],
            phone_number=request.form['phone_number'],
            website=request.form['website'],
            password=request.form['password'],
            email=request.form['email'],
            username=request.form['username'],
            color=request.form['color'],  # Сохраняем цвет в базе данных
            image_path=image_path,  # Сохраняем путь к изображению
            user_id=current_user.id  # Связываем пароль с текущим пользователем
        )

        # Добавляем объект пароля в сессию и сохраняем его в базе данных
        db.session.add(new_password)
        db.session.commit()

        # После сохранения пароля перенаправляем пользователя на страницу профиля
        return redirect(url_for('profile'))





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
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['repeat-password']

        # Проверяем уникальность логина и почты
        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже зарегистрирован!', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем пользователя уже зарегистрирован!', 'error')
            return redirect(url_for('register'))

         # Добавлены дополнительные проверки на валидность логина и почты
        if not (3 <= len(username) <= 12 and username.isalnum()):
            flash('Логин должен содержать от 3 до 12 символов и состоять только из латинских букв и цифр', 'error')
            return redirect(url_for('register'))
        if not validate_email(email):
            flash('Пожалуйста, введите действительный адрес электронной почты', 'error')
            return redirect(url_for('register'))

        # Проверяем соответствие пароля с подтверждением
        if password != confirm_password:
            flash('Пароли не совпадают, перепроверьте их вручную!', 'error')
            return redirect(url_for('register'))

        # Проверяем дополнительные условия валидации пароля
        if len(password) < 8 or len(password) > 20:
            flash('Пароль должен содержать от 8 до 20 символов', 'error')
            return redirect(url_for('register'))
        if not any(char.isupper() for char in password):
            flash('Пароль должен содержать хотя бы одну заглавную букву', 'error')
            return redirect(url_for('register'))
        if not any(char.islower() for char in password):
            flash('Пароль должен содержать хотя бы одну строчную букву', 'error')
            return redirect(url_for('register'))
        if not any(char.isdigit() for char in password):
            flash('Пароль должен содержать хотя бы одну цифру', 'error')
            return redirect(url_for('register'))
        if not any(char.isalnum() for char in password):
            flash('Пароль должен содержать хотя бы один спецсимвол', 'error')
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
            return redirect(url_for('reset_password_successfully'))
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
            confirm_password = request.form['confirm-password']  # Получаем подтверждение пароля
            if password != confirm_password:  # Проверяем, что пароли совпадают
                errors = [('error', 'Пароли не совпадают, перепроверьте их вручную!')]  # Создаем список ошибок
                return jsonify({'success': False, 'errors': errors}), 400  # Возвращаем ошибку с соответствующим статусом
            user.password = generate_password_hash(password)
            user.reset_token = None
            user.reset_token_expiration = None
            db.session.commit()
            return jsonify({'success': True})  # Возвращаем JSON-ответ при успешной смене пароля
        return render_template('reset-password.html', token=token)
    else:
        return jsonify({'error': 'Недействительный или просроченный токен сброса пароля'}), 400

# def delete_user_by_username(username):
#     with app.app_context():
#         user = User.query.filter_by(username=username).first()
#         if user:
#             # Check if there are associated passwords and delete them
#             for password in user.passwords:
#                 db.session.delete(password)
#             db.session.delete(user)
#             db.session.commit()
#             print(f"User with username '{username}' and associated passwords successfully deleted.")
#         else:
#             print(f"User with username '{username}' not found.")
#
# # Example usage:
# delete_user_by_username('sudden')


@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    if 'file' not in request.files:
        return 'No file part', 400

    file = request.files['file']

    if file.filename == '':
        return 'No selected file', 400

    # Генерация уникального имени файла
    filename = str(uuid.uuid4()) + secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Если пользователь уже загружал картинку, удаляем ее
    if current_user.is_authenticated and current_user.avatar_path:
        os.remove(current_user.avatar_path)

    # Сохранение новой картинки на сервере
    file.save(file_path)

    # Обновление пути файла в базе данных для авторизованного пользователя
    if current_user.is_authenticated:
        current_user.avatar_path = file_path
        db.session.commit()
        return 'File uploaded successfully', 200
    else:
        return 'User not authenticated', 401

@app.route('/delete_all_passwords', methods=['GET'])
@login_required
def delete_all_passwords():
    # Получаем текущего авторизованного пользователя
    user_id = current_user.id

    # Находим все записи в таблице Password для текущего пользователя и удаляем их
    passwords = Password.query.filter_by(user_id=user_id).all()
    for password in passwords:
        # Получаем путь к изображению
        image_path = password.image_path
        if image_path:
            # Проверяем, существует ли файл
            if os.path.exists(image_path):
                # Если файл существует, удаляем его
                try:
                    os.remove(image_path)
                    print(f"Изображение по пути {image_path} успешно удалено.")
                except Exception as e:
                    print(f"Ошибка при удалении изображения {image_path}: {e}")
            else:
                print(f"Изображение по пути {image_path} не найдено.")

        # Удаляем объект пароля из базы данных
        db.session.delete(password)

    # Сохраняем изменения в базе данных
    db.session.commit()

    # Перенаправляем пользователя на нужную страницу
    return redirect(url_for('profile'))


@app.route('/send_email', methods=['POST'])
@login_required
def send_email():
    # Получаем текущего пользователя
    user = current_user

    # Получаем все пароли пользователя из базы данных
    passwords = Password.query.filter_by(user_id=user.id).all()

    # Формируем текст сообщения для письма
    message_body = 'Список ваших паролей:\n\n'
    for password in passwords:
        message_body += f"Категория: {password.category}\n"
        message_body += f"Описание: {password.description}\n"
        message_body += f"Логин: {password.username}\n"
        message_body += f"Пароль: {password.password}\n\n"

    # Отправляем письмо на адрес пользователя
    try:
        send_email_to_user(user.email, message_body)
        return jsonify({'message': 'Письмо успешно отправлено'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def send_email_to_user(recipient_email, message_body):
    # Отправляем письмо на адрес получателя
    msg = Message('Ваши пароли', sender='noreply@example.com', recipients=[recipient_email])
    msg.body = message_body
    mail.send(msg)


@app.route('/delete-password/<int:password_id>', methods=['DELETE'])
def delete_password(password_id):
    password = Password.query.get_or_404(password_id)

    # Проверяем, есть ли путь к изображению в объекте пароля
    if password.image_path:
        # Получаем полный путь к изображению на сервере
        image_path = 'static/' + password.image_path

        # Проверяем существует ли файл по указанному пути
        if os.path.exists(image_path):
            try:
                os.remove(image_path)
                print(f"Изображение по пути {image_path} успешно удалено.")
            except Exception as e:
                print(f"Ошибка при удалении изображения {image_path}: {e}")
        else:
            print(f"Изображение по пути {image_path} не найдено.")

    db.session.delete(password)
    db.session.commit()

    return jsonify({'message': 'Password deleted successfully'}), 200

@app.route('/get_password_data/<int:password_id>', methods=['GET'])
def get_password_data(password_id):
    # Fetch password data from the database based on the password_id
    password = Password.query.filter_by(id=password_id).first()

    # Check if the password exists
    if password:
        # Convert the password data to a dictionary
        password_data = {
            'id': password.id,
            'title': password.title,
            'username': password.username,
            'category': password.category,
            'phone_number': password.phone_number,
            'website': password.website,
            'email': password.email,
            'password': password.password,
            'description': password.description
        }
        return jsonify(password_data)
    else:
        # If password with given ID doesn't exist, return 404 Not Found
        return jsonify({'error': 'Password not found'}), 404

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Функция для генерации уникального имени файла
def generate_unique_filename(filename):
    return str(uuid.uuid4()) + secure_filename(filename)

# Функция для проверки разрешенных расширений файлов
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/update-password', methods=['POST'])
def update_password():
    # Получаем данные из формы
    password_id = request.form.get('id-edit')
    title = request.form.get('title-edit')
    username = request.form.get('username-edit')
    category = request.form.get('category-edit')
    color = request.form.get('color-edit')
    phone_number = request.form.get('phone_number-edit')
    website = request.form.get('website-edit')
    email = request.form.get('email-edit')
    password_edit = request.form.get('password-edit')
    description = request.form.get('description-edit')

    # Получаем файл изображения из формы, если он был загружен
    image = request.files.get('image-edit')

    # Находим объект пароля в базе данных по его идентификатору
    password = Password.query.get_or_404(password_id)

    # Обновляем данные пароля
    password.title = title
    password.username = username
    password.category = category
    password.color = color
    password.phone_number = phone_number
    password.website = website
    password.email = email
    password.password = password_edit
    password.description = description

    # Если было загружено новое изображение
    if image and image.filename != '':
        # Удаляем старое изображение, если оно существует
        if password.image_path:
            image_path_parts = password.image_path.split('uploads/')
            if len(image_path_parts) > 1:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image_path_parts[1]))

        # Генерируем уникальное имя файла
        filename = str(uuid4()) + secure_filename(image.filename)

        # Сохраняем изображение на сервере
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Сохраняем путь к изображению в объекте пароля
        password.image_path = os.path.join('uploads', filename)

    # Сохраняем изменения в базе данных
    db.session.commit()

    # Перенаправляем пользователя обратно на страницу профиля или на другую страницу
    return redirect(url_for('profile'))