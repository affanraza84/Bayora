FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd -g 10001 bayora && \
    useradd -u 10001 -g bayora -s /bin/bash -m bayora

COPY services/control-plane/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY services/control-plane /app/services/control-plane

USER bayora:bayora

EXPOSE 8000

CMD ["uvicorn", "services.control-plane.main:app", "--host", "0.0.0.0", "--port", "8000"]
