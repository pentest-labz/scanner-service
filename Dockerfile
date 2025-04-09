FROM python:3.13-alpine

# Set the working directory.
WORKDIR /app

# Copy and install dependencies.
COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy the application code.
COPY . .

# Expose port 8001.
EXPOSE 8001

# Run the service.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
