FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY mdrj ./mdrj
COPY configs ./configs
COPY scripts ./scripts
COPY docker ./docker

RUN apt-get update \ 
    && apt-get install -y --no-install-recommends curl bash \ 
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip && pip install .

CMD ["python", "-m", "mdrj.cli", "node", "--config", "/app/configs/node.example.yaml"]
