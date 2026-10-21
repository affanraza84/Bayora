FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd -g 10001 bayora && \
    useradd -u 10001 -g bayora -s /bin/bash -m bayora

COPY services/model-gateway/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/model-gateway /app/services/model-gateway

USER bayora:bayora

EXPOSE 8003

CMD ["python", "-m", "http.server", "8003"]
