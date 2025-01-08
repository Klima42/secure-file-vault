FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create upload directory
RUN mkdir -p uploads && chmod 777 uploads

# Create instance directory for SQLite database
RUN mkdir -p instance && chmod 777 instance

EXPOSE 5000

CMD ["python", "run.py"]