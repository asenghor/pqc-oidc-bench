# Build context: the repository root.
#   docker build -f services/echo/Dockerfile .
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv
COPY services/echo/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY services/echo/echo ./echo

# Unprivileged user; TLS material is mounted by the Compose stack.
USER 65534:65534
EXPOSE 8443
CMD ["python", "-m", "echo"]
