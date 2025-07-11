# Use official Python image from the Docker Hub
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 53468 available to the world outside this container
EXPOSE 53468

# Define environment variable
ENV PYTHONPATH=/app
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=53468

# Run app.py when the container launches
CMD ["python", "tls_certificate_scanner/app.py"]
