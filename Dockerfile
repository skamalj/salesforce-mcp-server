FROM python:3.11-slim

WORKDIR /app

# Just this is enough
COPY src/ /app/

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "server.py"]
