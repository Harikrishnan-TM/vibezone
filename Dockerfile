# Use official Python image
FROM python:3.11-slim

# Set workdir
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your code
COPY . .

# Expose the port
ENV PORT 8080
EXPOSE 8080

# Run Daphne
CMD ["daphne", "core.asgi:application"]
