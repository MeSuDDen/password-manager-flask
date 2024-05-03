# Базовый образ для Python
FROM python:3.11

# Установка рабочей директории в контейнере
WORKDIR /app

# Копирование файлов зависимостей и установка их
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Копирование остальных файлов проекта
COPY . .

# Установка переменной среды для Flask
ENV FLASK_APP=app.py

# Команда для запуска приложения Flask
CMD ["flask", "run", "--host=0.0.0.0"]
