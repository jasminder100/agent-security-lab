FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app app
COPY runner runner
COPY config config
COPY tests tests
COPY scripts scripts
COPY pytest.ini .

# Run as a normal user, not root
RUN useradd --create-home appuser \
    && mkdir -p reports/results reports/scratch \
    && chown -R appuser /app
USER appuser

CMD ["bash", "scripts/check.sh"]
