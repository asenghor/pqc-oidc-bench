# Build context: the repository root.
#   docker build -f services/echo/Dockerfile .
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

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
