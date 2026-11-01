# OT Watch — image runtime (dashboard live + collecte)
FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --quiet --no-cache-dir -r requirements.txt
COPY . .
# sécurité : utilisateur non-root
RUN useradd -m otwatch && chown -R otwatch:otwatch /app
USER otwatch
EXPOSE 8000
ENV OTWATCH_HOST=0.0.0.0 OTWATCH_PORT=8000 AUTO_REFRESH_SECONDS=1800
HEALTHCHECK --interval=60s --timeout=5s CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/meta', timeout=4)" || exit 1
CMD ["python3", "server.py"]
