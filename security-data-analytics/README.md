# SDA
## Description
The ``Security Data Analytics`` (SDA) project is designed to recieve PCAP chunk from Security Data Collection, analyse them and genereate a report to send to Security Decision.

## Prerequisites
You need to download and deploy SPDS database https://git.optare.net/cttc/p-10590-opensec-6g/security/spds and Security Data Collection https://git.optare.net/cttc/p-10590-opensec-6g/security/security-data-collection

## Configuration
The project use `.env` file for development environment profile:

- `.env.development`: Variables for the development environment (by default).

## Deployment
Before making any changes or deploying for the first time, it is necessary to perform a build. 
```bash
docker-compose build 
```
_Note: `.env.development` file is chosen by default_

Then it is possible to initialize the containers:

```bash
docker-compose up
```

Alternatively, it is possible to use one single command to replace the two commands above:
```bash
docker-compose up --build
```


## Integrations
To maintain integration with the rest of components, the used network is `closed_loop_network`.
````yaml
networks:
  closed_loop_network:
    driver: bridge
    external: true 
````

## Containers

Existing containers:
- `security-data-analytics`

# Project Structure

- `Dockerfile`: Defines the Docker image for the application.
- `docker-compose.yml`: Docker Compose configuration for running the application and its services.
- `dependencies/`: Contains dependencies
  - `requirements.txt`: List of Python dependencies.    
- `src/`: Source code.
  - `broker/`: Broker Consumer and Producer logic.
  - `database`: Database interactions and utilities.
  - `modules/`: SDA modules.
  - `pcap/`: Folder containing some PCAP files.
  - `services/`: Services for SDA logic.
  - `utils/`: Functions and scripts for logic utilities.
  - `main.py`: Script to manage everything.
  

## Logging System
The project includes a flexible logging system. Logs are automatically collected by Docker and can be accessed via the Docker CLI.

To view the logs for a specific container, use the following command:
```bash
docker logs [CONTAINER_ID]
```
Replace [CONTAINER_ID] with the ID or the name of your container.


## Modules
### Anomaly Detection Module
Recieves PCAPs in the corresponding broker topic and analyses them.

### Data Processing & Transformation Module
Recieves the PCAP chunks and reconstruct the PCAP file.

### Real Time Analytics & Stream Processing Module
Dashboard and feedback analysis.

## Services
### Alert
Sends alerts and security reports through the corresponding broker topic to Security Decision.

### Anomaly Detection Engine
Logic to process the PCAP file and detect the presence of DDoS.

### Dash Application
Logic for Dashboar Application that helps visualise the security reports.

### Feedback & Optimization Engine
Logic for evaluating the efficacy of the Deep Learning model.

### Real Time Analytics & Stream Processing
Data transformation and processing.

### Reporting
Generates the reports, keeping them in the SPDS database.


# Authors
v1.0.0  mpires@optaresolutions.com
        pvieira@optaresolutions.com