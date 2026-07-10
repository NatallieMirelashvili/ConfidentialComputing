# Management Server (User<->Server side) container image.
#
# Build context is project_itself/ so that `python -m server.main` resolves the
# `server` package. Only the `server/` package is copied in (see .dockerignore).
FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for better layer caching.
COPY server/requirements.txt server/requirements.txt
RUN pip install --no-cache-dir -r server/requirements.txt

# Application code.
COPY server/ server/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MS_API_HOST=0.0.0.0 \
    MS_API_PORT=8000 \
    MS_USER_SECURITY=tls \
    MS_DEVICE_LINK=stub \
    MS_DEVICE_HOST=0.0.0.0 \
    MS_DEVICE_PORT=9000

EXPOSE 8000
EXPOSE 9000


# User<->Server transport mode is chosen via MS_USER_SECURITY (tls | aesgcm).
# In TLS mode a self-signed cert is generated on first run under
# /app/server/certs (persist it with a volume — see docker-compose.yml).
CMD ["python", "-m", "server.main"]
