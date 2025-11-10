FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create directories for uploads and documents
RUN mkdir -p /app/uploads/avatars
RUN mkdir -p /app/documents/statements
RUN mkdir -p /app/documents/contracts
RUN mkdir -p /app/documents/receipts
RUN mkdir -p /app/documents/admin
RUN chmod -R 777 /app/uploads
RUN chmod -R 777 /app/documents

# Expose port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "app.py"]
