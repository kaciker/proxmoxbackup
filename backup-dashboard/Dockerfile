FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/backup-dashboard
COPY app.py icon.svg manifest.webmanifest apple-touch-icon.png ./

EXPOSE 8788
CMD ["python3", "/opt/backup-dashboard/app.py"]
