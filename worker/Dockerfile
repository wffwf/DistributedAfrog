FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY worker.py .
COPY scripts/download_afrog.sh /usr/local/bin/download-afrog
RUN chmod +x /usr/local/bin/download-afrog

ENV AFROG_BIN=/app/afrog-bin/afrog

CMD ["python", "worker.py"]