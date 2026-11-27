FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOST=0.0.0.0 \
    APP_PORT=5000

WORKDIR /srv/app

# Hardening: Tampal pakej OS Debian
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Pasang library aplikasi, kemudian buang pip & ensurepip daripada imej runtime (Zero-Trust Hardening)
COPY app/requirements.txt ./app/requirements.txt
RUN pip install --no-cache-dir -r app/requirements.txt \
    && rm -rf /usr/local/lib/python3.12/ensurepip \
              /usr/local/lib/python3.12/site-packages/pip* \
              /usr/local/bin/pip*

# Salin kod aplikasi
COPY app/ ./app/

# Hardening: Cipta dan tukar ke pengguna non-root (Zero Trust / Least Privilege)
RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /srv/app

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')" || exit 1

CMD ["python", "-m", "app.app"]