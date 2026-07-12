FROM python:3.12-slim

WORKDIR /app

# System-Libs für python3-saml (xmlsec1) — Build- + Runtime-Abhängigkeiten.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential pkg-config \
      libxml2-dev libxmlsec1-dev libxmlsec1-openssl libssl-dev libltdl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /app/

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
