# Kubyk

### v 0.11

### Python/Flask based template Web UI.

![Alt text](https://github.com/ratibor78/kubyk/blob/master/kubyk1.png?raw=true "Kubyk WEB UI main page")
![Alt text](https://github.com/ratibor78/kubyk/blob/master/kubyk2.png?raw=true "Kubyk WEB UI main page menu")
![Alt text](https://github.com/ratibor78/kubyk/blob/master/kubyk3.png?raw=true "Kubyk WEB UI users admin")

Project based on Bootstrap and SQlite, for helping you with creating own WEB UI for some automation tasks. 

From box you'll get a user levels, small Sqlite database for storing any data, some examples of using Python and Flask. Also there is a Dockerfile ready for creating Docker image for quick start. 

## Check what it is: 

```
$ docker run -d --name kubyk -p 80:80 ratibor78/kubyk
```
After open http://yourip:80 in your browser and login = admin, password = admin


## Installation

### Quick start on your local PC

1) Clone the repository, create environment and install requirements
```sh
$ cd kubyk
$ virtualenv venv && source venv/bin/activate
$ pip install -r requirements.txt
$ python kubyk.py 
```
Open in your browser http://127.0.0.1:5000 

### Compile and run with Docker 
1) Clone the repository

```
$ cd kubyk
$ docker build -t anyname/kubyk .
$ docker run -d --name kubyk -p 80:80 anyname/kubyk
```
Use it. 
