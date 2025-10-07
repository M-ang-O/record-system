from flask import Flask, render_template, request, jsonify
from datetime import datetime, timedelta
import json
import os
from threading import Lock

app = Flask(__name__)

# Хранилище данных в памяти (в продакшене используйте базу данных)
users_data = []
data_lock = Lock()

# Время активации кнопки (18:00)
ACTIVATION_HOUR = 18
ACTIVATION_MINUTE = 0


def get_activation_time():
    """Возвращает время следующей активации кнопки"""
    now = datetime.now()
    activation_time = now.replace(hour=ACTIVATION_HOUR, minute=ACTIVATION_MINUTE, second=0, microsecond=0)

    # Если уже прошло 18:00 сегодня, устанавливаем на завтра
    if now > activation_time:
        activation_time += timedelta(days=1)

    return activation_time


def is_button_active():
    """Проверяет, активна ли кнопка в текущий момент"""
    now = datetime.now()
    activation_time = get_activation_time()
    return now >= activation_time


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/users', methods=['GET'])
def get_users():
    """Получить список всех пользователей"""
    with data_lock:
        # Сортируем по времени записи (старые сначала)
        sorted_users = sorted(users_data, key=lambda x: x['time'])
        return jsonify(sorted_users)


@app.route('/api/users', methods=['POST'])
def add_user():
    """Добавить нового пользователя"""
    data = request.get_json()

    if not data or 'name' not in data:
        return jsonify({'error': 'Имя обязательно'}), 400

    name = data['name'].strip()
    if not name:
        return jsonify({'error': 'Имя не может быть пустым'}), 400

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
            'time': datetime.now().isoformat()
        }

        users_data.append(user_record)

    return jsonify(user_record), 201


@app.route('/api/status', methods=['GET'])
def get_status():
    """Получить статус кнопки и время до активации"""
    now = datetime.now()
    activation_time = get_activation_time()
    time_diff = activation_time - now

    status = {
        'is_active': is_button_active(),
        'time_until_active': max(0, int(time_diff.total_seconds())),
        'activation_time': activation_time.isoformat(),
        'total_users': len(users_data)
    }

    return jsonify(status)


@app.route('/api/reset', methods=['POST'])
def reset_data():
    """Сбросить данные (для тестирования)"""
    password = request.get_json().get('password') if request.get_json() else None
    if password != 'admin123':  # Простой пароль для демо
        return jsonify({'error': 'Неверный пароль'}), 403

    with data_lock:
        users_data.clear()

    return jsonify({'message': 'Данные сброшены'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)