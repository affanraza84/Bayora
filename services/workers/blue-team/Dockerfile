FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd -g 10001 bayora && \
    useradd -u 10001 -g bayora -s /bin/bash -m bayora

COPY services/workers/blue-team/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/workers/blue-team /app/services/workers/blue-team

USER bayora:bayora

EXPOSE 8002

CMD ["python", "-c", "print('Bayora Blue-Team Worker Initialized')"]
