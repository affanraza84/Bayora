FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd -g 10001 bayora && \
    useradd -u 10001 -g bayora -s /bin/bash -m bayora

COPY services/evaluator/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/evaluator /app/services/evaluator

USER bayora:bayora

EXPOSE 8005

CMD ["python", "-m", "http.server", "8005"]
