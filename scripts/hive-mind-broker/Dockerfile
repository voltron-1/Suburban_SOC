# Hive-Mind Broker — authenticated router-block dispatcher (#109).
# Slim image: only needs Python + the pure-wheel deps (asyncssh/cryptography ship
# manylinux wheels, so no build toolchain required).
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Router inventory (inventory.yaml) and the SSH key are mounted at runtime by
# docker-compose — never baked into the image (they are host-specific secrets).
EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
