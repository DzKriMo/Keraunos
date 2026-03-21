FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    git \
    ca-certificates \
    wget \
    xdg-utils \
    nmap \
    sqlmap \
    metasploit-framework \
    wpscan \
    gobuster \
    nikto \
    nuclei \
    ffuf \
    sslscan \
    dnsrecon \
    enum4linux-ng \
    hydra \
    exploitdb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN python3 -m pip install --break-system-packages --no-cache-dir -r /app/requirements.txt && \
    python3 -m playwright install --with-deps chromium

COPY . /app

EXPOSE 8000

ENV KERAUNOS_LLM_PROVIDER=openrouter
ENV KERAUNOS_LLM_MODEL=stepfun/step-3.5-flash:free

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
