FROM python:3.7

WORKDIR /usr/src/azure_checks
RUN apt-get update
RUN apt-get install python3-dev -y

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python3", "-u","./audit.py" ]

