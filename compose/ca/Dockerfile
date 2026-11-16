# One-shot container that fills the shared volume with the ephemeral TLS
# material of the local stack. Build context: the repository root.
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv
COPY compose/ca/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY compose/ca/generate.py ./generate.py

CMD ["python", "generate.py"]
