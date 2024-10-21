# Use an official Python runtime as a base image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /security_data_analytics_app

RUN apt-get update 
RUN apt-get install -y git 
RUN apt-get install -y netcat-traditional tshark
RUN pip install numpy==1.25.2
# Install any needed packages specified in requirements.txt
COPY dependencies/requirements.txt ./dependencies/
RUN pip install --no-cache-dir -r dependencies/requirements.txt

# Copy the current directory contents into the container at /app
COPY src/ ./src/
#COPY tests/ ./tests/
# Make port 5002 available to the world outside this container
EXPOSE 5002

# Run the app when the container launches
CMD ["python3", "src/main.py"]
