FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y git make g++ \
    && apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y libboost-all-dev libbsd-dev 


