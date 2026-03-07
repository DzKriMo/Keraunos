FROM kalilinux/kali-rolling

# Avoid interactive prompts during apt
ENV DEBIAN_FRONTEND=noninteractive

# Install core pentesting tools (Full 18-tool suite)
RUN apt update && apt install -y \
    nmap sqlmap metasploit-framework wpscan gobuster nikto \
    nuclei ffuf sslscan dnsrecon enum4linux-ng hydra \
    exploitdb python3 python3-pip curl git \
    && apt clean

WORKDIR /app
COPY . /app

# Install dependencies using --break-system-packages (safe in a container)
RUN pip3 install --break-system-packages -r requirements.txt

EXPOSE 8000
ENV KERAUNOS_LLM_URL=http://host.docker.internal:11434

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
