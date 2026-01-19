FROM python:3.11

# -----------------------------
# Install build dependencies
# -----------------------------
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    ca-certificates \
    file \
    binutils \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------
# Install radare2 (official)
# -----------------------------
RUN git clone https://github.com/radareorg/radare2.git /opt/radare2 && \
    cd /opt/radare2 && \
    sys/install.sh && \
    r2 -v

# -----------------------------
# Set working directory
# -----------------------------
WORKDIR /app

# -----------------------------
# Install Python deps
# -----------------------------
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# -----------------------------
# Copy app
# -----------------------------
COPY . .

CMD ["python", "ingest_file.py"]
