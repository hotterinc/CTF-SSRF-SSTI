FROM python:3.11-slim

WORKDIR /app

RUN useradd -m ctf

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY templates ./templates
COPY static ./static

RUN echo "CTF{ssti_templ4te_escape_is_0pt1c4l_54d91b}" > /home/flag.txt \
    && chmod 444 /home/flag.txt

RUN chown -R ctf:ctf /app

USER ctf

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
