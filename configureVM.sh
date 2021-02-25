#!/bin/bash

# Update repository information and packages
sudo apt-get update -y
sudo apt-get upgrade -y

########################
### Install software ###
########################

## Basic tools
## Midnight Commander ##
sudo apt install mc -y
## Python3 pip ##
sudo apt install python3-pip -y
## nmap ##
sudo apt install nmap -y
## Putty terminal ##
sudo apt install putty -y
## Wireshark ##
sudo apt install wireshark -y
## Filezilla ##
sudo apt install filezilla -y
## Python3 sslscan ##
pip3 install sslscan
## Python3 OpenSSL ##
pip3 install pyopenssl


################################
### Settings and preferences ###
################################



