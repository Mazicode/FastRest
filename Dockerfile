# Use an appropriate base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy application code
COPY ./app /app

# Copy and install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Set PYTHONPATH to /app
ENV PYTHONPATH=/app

# Expose port
EXPOSE 8000

# Command to run the app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
