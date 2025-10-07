from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from datetime import datetime, timedelta
import json
import os
import hashlib
from threading import Lock
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Хранилище данных
users_data = []
blocked_users = []
admin_settings = {
    'activation_hour': 18,
    'activation_minute': 0,
    'is_registration_open': True
}
user_accounts = {
    'admin': {
        'password': hashlib.sha256('admin123'.encode()).hexdigest(),
        'role': 'admin'
    }
}

data_lock = Lock()


def get_activation_time():
    """Возвращает время следующей активации кнопки"""
    now = datetime.now()
    activation_time = now.replace(
        hour=admin_settings['activation_hour'],
        minute=admin_settings['activation_minute'],
        second=0,
        microsecond=0
    )

    if now > activation_time:
        activation_time += timedelta(days=1)

    return activation_time


def is_button_active():
    """Проверяет, активна ли кнопка в текущий момент"""
    if not admin_settings['is_registration_open']:
        return False

    now = datetime.now()
    activation_time = get_activation_time()
    return now >= activation_time


def is_logged_in():
    return 'username' in session


def is_admin():
    return session.get('role') == 'admin'


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


@app.route('/')
def index():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'], is_admin=is_admin())


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if username in user_accounts and user_accounts[username]['password'] == hash_password(password):
            session['username'] = username
            session['role'] = user_accounts[username]['role']
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Неверное имя пользователя или пароль')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not password:
            return render_template('register.html', error='Заполните все поля')

        if password != confirm_password:
            return render_template('register.html', error='Пароли не совпадают')

        if username in user_accounts:
            return render_template('register.html', error='Пользователь уже существует')

        if len(username) < 3:
            return render_template('register.html', error='Имя пользователя должно быть не менее 3 символов')

        if len(password) < 4:
            return render_template('register.html', error='Пароль должен быть не менее 4 символов')

        user_accounts[username] = {
            'password': hash_password(password),
            'role': 'user'
        }

        session['username'] = username
        session['role'] = 'user'
        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# API Routes
@app.route('/api/users', methods=['GET'])
def get_users():
    if not is_logged_in():
        return jsonify({'error': 'Не авторизован'}), 401

    with data_lock:
        sorted_users = sorted(users_data, key=lambda x: x['time'])
        return jsonify(sorted_users)


@app.route('/api/users', methods=['POST'])
def add_user():
    if not is_logged_in():
        return jsonify({'error': 'Не авторизован'}), 401

    data = request.get_json()

    if not data or 'name' not in data:
        return jsonify({'error': 'Имя обязательно'}), 400

    name = data['name'].strip()
    if not name:
        return jsonify({'error': 'Имя не может быть пустым'}), 400

    # Проверяем, заблокирован ли пользователь
    if session['username'] in blocked_users:
        return jsonify({'error': 'Ваш аккаунт заблокирован'}), 403

    # Проверяем, активна ли кнопка
    if not is_button_active():
        return jsonify({'error': 'Запись еще не открыта'}), 403

    # Проверяем, не записывался ли уже пользователь с таким именем
    with data_lock:
        if any(user['name'].lower() == name.lower() for user in users_data):
            return jsonify({'error': 'Пользователь с таким именем уже записан'}), 409

        user_record = {
            'id': len(users_data) + 1,
            'name': name,
            'time': datetime.now().isoformat(),
            'registered_by': session['username']
        }

        users_data.append(user_record)

    return jsonify(user_record), 201


@app.route('/api/status', methods=['GET'])
def get_status():
    if not is_logged_in():
        return jsonify({'error': 'Не авторизован'}), 401

    now = datetime.now()
    activation_time = get_activation_time()
    time_diff = activation_time - now

    status = {
        'is_active': is_button_active(),
        'time_until_active': max(0, int(time_diff.total_seconds())),
        'activation_time': activation_time.isoformat(),
        'total_users': len(users_data),
        'is_registration_open': admin_settings['is_registration_open'],
        'current_user': session['username'],
        'is_blocked': session['username'] in blocked_users
    }

    return jsonify(status)


# Admin API Routes
@app.route('/api/admin/settings', methods=['GET'])
def get_admin_settings():
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Доступ запрещен'}), 403

    return jsonify(admin_settings)


@app.route('/api/admin/settings', methods=['POST'])
def update_admin_settings():
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Доступ запрещен'}), 403

    data = request.get_json()

    with data_lock:
        if 'activation_hour' in data:
            admin_settings['activation_hour'] = int(data['activation_hour'])
        if 'activation_minute' in data:
            admin_settings['activation_minute'] = int(data['activation_minute'])
        if 'is_registration_open' in data:
            admin_settings['is_registration_open'] = bool(data['is_registration_open'])

    return jsonify(admin_settings)


@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Доступ запрещен'}), 403

    with data_lock:
        user_list = []
        for username, user_data in user_accounts.items():
            if user_data['role'] != 'admin':  # Не показываем админов
                user_list.append({
                    'username': username,
                    'role': user_data['role'],
                    'is_blocked': username in blocked_users,
                    'records_count': len([u for u in users_data if u['registered_by'] == username])
                })

        return jsonify(user_list)


@app.route('/api/admin/users/<username>/block', methods=['POST'])
def block_user(username):
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Доступ запрещен'}), 403

    if username not in user_accounts or user_accounts[username]['role'] == 'admin':
        return jsonify({'error': 'Пользователь не найден'}), 404

    with data_lock:
        if username not in blocked_users:
            blocked_users.append(username)

    return jsonify({'message': f'Пользователь {username} заблокирован'})


@app.route('/api/admin/users/<username>/unblock', methods=['POST'])
def unblock_user(username):
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Доступ запрещен'}), 403

    with data_lock:
        if username in blocked_users:
            blocked_users.remove(username)

    return jsonify({'message': f'Пользователь {username} разблокирован'})


@app.route('/api/admin/records/<int:record_id>', methods=['DELETE'])
def delete_record(record_id):
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Доступ запрещен'}), 403

    with data_lock:
        global users_data
        users_data = [user for user in users_data if user['id'] != record_id]
        # Обновляем ID оставшихся записей
        for i, user in enumerate(users_data, 1):
            user['id'] = i

    return jsonify({'message': 'Запись удалена'})


@app.route('/api/admin/reset', methods=['POST'])
def reset_all_data():
    if not is_logged_in() or not is_admin():
        return jsonify({'error': 'Доступ запрещен'}), 403

    with data_lock:
        users_data.clear()
        blocked_users.clear()

    return jsonify({'message': 'Все данные сброшены'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)