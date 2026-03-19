# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Копируем requirements и устанавливаем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь проект
COPY . .

# Создаем папку для загрузок
RUN mkdir -p /tmp/uploads && chmod 777 /tmp/uploads

# Делаем скрипты исполняемыми
RUN chmod +x migrate_render.py || true

# Указываем порт
EXPOSE 10000

# Команда для запуска - сначала миграция, потом приложение
CMD python migrate_render.py && gunicorn -k eventlet -w 1 --bind 0.0.0.0:$PORT app:app
