#!/bin/bash

./gradlew build
docker build -t eps:latest .
docker run -it --rm -p 8888:8080 eps:latest
