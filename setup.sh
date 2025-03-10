#!/bin/bash

# Stop FreeRADIUS service
sudo systemctl stop freeradius

# Create certificates directory if it doesn't exist
sudo mkdir -p /etc/freeradius/3.0/certs

# Copy our configurations
sudo cp radius_configs/sql /etc/freeradius/3.0/mods-available/sql
sudo cp radius_configs/eap /etc/freeradius/3.0/mods-available/eap
sudo cp radius_configs/clients.conf /etc/freeradius/3.0/clients.conf

# Enable SQL module
cd /etc/freeradius/3.0/mods-enabled
sudo ln -sf ../mods-available/sql .

# Set proper permissions
sudo chown -R freerad:freerad /etc/freeradius/3.0/
sudo chmod 640 /etc/freeradius/3.0/mods-available/sql

# Generate SSL certificates for EAP
cd /etc/freeradius/3.0/certs
sudo openssl dhparam -out dh 2048
sudo openssl req -new -x509 -keyout server.key -out server.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=radius.example.com"

# Start FreeRADIUS service
sudo systemctl start freeradius

# Create virtual environment and install Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
