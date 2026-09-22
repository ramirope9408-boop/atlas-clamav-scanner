FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends clamav clamav-daemon clamav-freshclam ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY entrypoint.sh .
RUN chmod +x /app/entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
