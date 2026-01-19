FROM python:3.11-slim

WORKDIR /app

RUN useradd -m ctf

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY templates ./templates
COPY static ./static

RUN echo "CTF{SSTI_is_fun_and_d4ng3r0us}" > /home/flag.txt \
    && chmod 444 /home/flag.txt

RUN chown -R ctf:ctf /app

USER ctf

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
