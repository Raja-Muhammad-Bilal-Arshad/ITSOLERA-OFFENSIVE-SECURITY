# CVE 2021 3156 Lab Setup

This container runs Ubuntu 20.04 with sudo version 1.8.31 compiled from source. The environment is isolated and ready for exploit development.

1. Open your terminal in the `lab` directory.
2. Build and start the container by running `docker-compose up -d --build`.
3. Access the container shell as the unprivileged user by running `docker exec -it cve_2021_3156_lab /bin/bash`.
4. Test your Python scripts by copying them into the container using `docker cp ../exploit/exploit.py cve_2021_3156_lab:/home/tester/`.
5. Reset the environment completely by running `docker-compose down` followed by `docker-compose up -d`.
