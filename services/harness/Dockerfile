# Build context: the repository root.
#   docker build -f services/harness/Dockerfile .
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MATRIX_FILE=/bench/matrix.yaml

WORKDIR /srv
COPY services/harness/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY bench/matrix.yaml /bench/matrix.yaml
COPY services/harness/harness ./harness

USER 65534:65534
ENTRYPOINT ["python", "-m", "harness"]
CMD ["smoke"]
