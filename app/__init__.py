from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import config

app = Flask(__name__)

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config.from_object('config.DevelopmentConfig')
db = SQLAlchemy(app)

from app import webui
