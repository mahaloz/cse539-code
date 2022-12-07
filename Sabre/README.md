# Sabre


Here we implement Sabre: A Sender Anonymous Messaging System with Fast Audits. There are two main phases in Sabre, namely, Auditing and Writing into the database. 


**Installing the dependencies**

`sudo apt-get install make`

`sudo apt-get update && sudo apt-get upgrade`

`sudo apt-get install g++`

`sudo apt-get install libboost-all-dev`

`sudo apt-get install -y libbsd-dev`


**Sabre Writing**

`cd Sabre-write`

`make`

`./sabre`

**Sabre Writing**

`cd 2PC`

`make`

`./simulator`

`./verifier`





