FROM kalilinux/kali-rolling
RUN apt update && apt install -y nmap sqlmap metasploit-framework wpscan gobuster nikto
RUN apt install -y python3 python3-pip
WORKDIR /app
COPY . /app
RUN pip3 install -r requirements.txt
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
