# Kubyk

### v 0.11

### Python/Flask based template Web UI.

![Alt text](https://github.com/ratibor78/kubyk/blob/master/kubyk1.png?raw=true "Kubyk WEB UI main page")
![Alt text](https://github.com/ratibor78/kubyk/blob/master/kubyk2.png?raw=true "Kubyk WEB UI main page menu")
![Alt text](https://github.com/ratibor78/kubyk/blob/master/kubyk3.png?raw=true "Kubyk WEB UI users admin")

Based on Bootstrap and SQlite, for helping you to create own WEB UI projects for some automation tasks. 

From box you'll get a user levels, small Sqlite database for storing some data, some examples of using Python and Flask. Soon there be the Docker file and Docker Image ready for deploying and some addition documentation about it.

## Installation

### Quick start on your local PC

1) Clone the repository, create environment and install requirements
```sh
$ cd kubyk
$ virtualenv venv && source venv/bin/activate
$ pip install -r requirements.txt
$ python app.py 

Open in your browser http://127.0.0.1:5000 
