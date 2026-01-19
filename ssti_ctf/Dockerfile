FROM python:3.9-slim

WORKDIR /app

RUN useradd -m ctf

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код приложения
COPY server.py .
COPY templates ./templates
COPY static ./static

# --- СОЗДАНИЕ ФЛАГА ---
# Создаем файл флага в указанной директории
RUN echo "CTF{SSTI_is_fun_and_d4ng3r0us}" > /home/flag.txt

# Настраиваем права доступа:
# 1. Флаг может читать кто угодно (включая нашего пользователя ctf), но писать в него нельзя.
RUN chmod 444 /home/flag.txt

# 2. Отдаем папку приложения пользователю ctf, чтобы он мог создавать users.csv
RUN chown -R ctf:ctf /app

# Переключаемся на пользователя ctf
USER ctf

# Открываем порт 8000
EXPOSE 8000

# Запускаем сервер
CMD ["python", "server.py"]