FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOST=0.0.0.0 \
    APP_PORT=5000

WORKDIR /srv/app

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt ./app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r app/requirements.txt \
    && pip uninstall -y setuptools wheel jaraco.context || true \
    && rm -rf /usr/local/lib/python3.12/ensurepip \
    && find /usr/local/lib /usr/lib -iname "*setuptools*" -exec rm -rf {} +

COPY app/ ./app/

RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /srv/app

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')" || exit 1

CMD ["python", "-m", "app.app"]