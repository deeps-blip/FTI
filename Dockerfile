FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    ca-certificates \
    file \
    binutils \
    pkg-config \
    strace \
    && rm -rf /var/lib/apt/lists/*

# Install radare2
RUN git clone --depth 1 https://github.com/radareorg/radare2.git /opt/radare2 && \
    cd /opt/radare2 && \
    sys/install.sh

# Create directories
RUN mkdir -p /sandbox/malware
RUN mkdir -p /app/data/features

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Add ingestion entrypoint
COPY docker_entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD [ "uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000" ]
