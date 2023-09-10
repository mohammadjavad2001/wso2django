# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory to /app
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --ignore-installed -r requirements.txt
# Copy the current directory contents into the container at /app


# Expose the port that Django will run on
EXPOSE 8000

# Start the Django development server with auto-reloading
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]