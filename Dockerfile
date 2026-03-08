FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1000 appuser \
    && useradd --system --uid 1000 --gid appuser appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 5000

ENTRYPOINT ["tini", "--"]
CMD ["python", "cli.py", "serve", "--host", "0.0.0.0"]
