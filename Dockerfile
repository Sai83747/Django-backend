# Use Python 3.9
FROM python:3.9

# Set working directory inside the container
WORKDIR /app

# Copy the requirements file first
COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy all other project files
COPY . /app/

# Expose port for Django
EXPOSE 8000

# Run Django server directly (no wait_for_db)
CMD ["sh", "-c", "python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]
