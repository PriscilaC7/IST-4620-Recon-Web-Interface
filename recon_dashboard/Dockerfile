FROM python:3.10-slim

WORKDIR /app

# Install system dependencies required for some Python packages
RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose the Gradio default port
EXPOSE 7860

# Ensure Gradio binds to all network interfaces
ENV GRADIO_SERVER_NAME="0.0.0.0"

CMD ["python", "app.py"]
