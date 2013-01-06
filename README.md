========== SNIFF'EIRB ==========

Welcome to our 3rd year ENSEIRB's PR311 projet.

If you want to install Sniff'eirb, you will need to install some packages:
- python :
- scapy:
- python-pymongo:
- mongodb :

------------------------------------
Installation on Ubuntu 12.04 LTS:

sudo apt-get install mongodb
sudo apt-get install scapy
sudo apt-get install python-pymongo

-------------------------------------
Installation on openSuSe 12.1..

As root, follow these steps

MONGODB :
-zypper install mongodb
if it does not exist, add the repo :
-zypper addrepo http://download.opensuse.org/repositories/server:database/openSUSE_12.1/server:databse.repo
-zypper refresh
To start mongoDB Server write the command : mongod

-------------------------------------
Installation on Windows:
Don't bother yourself with it, it does NOT work on Windows
