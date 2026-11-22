FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1000 appuser \
    && useradd --system --uid 1000 --gid appuser appuser

WORKDIR /app

COPY requirements.txt .
# git is needed only to install omada-openapi from its repository.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove git \
    && rm -rf /var/lib/apt/lists/*

COPY --chown=appuser:appuser . .

RUN mkdir -p /app/docs && chown appuser:appuser /app/docs

USER appuser

EXPOSE 5000

ENTRYPOINT ["tini", "--"]
CMD ["python", "cli.py", "serve", "--host", "0.0.0.0"]
