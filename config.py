class Config(object):
    SQLALCHEMY_DATABASE_URI = 'sqlite:////opt/sqlite/database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class ProductionConfig(Config):
    DEBUG = False
    DEVELOPMENT = False
    SEND_TO_SLACK = True


class DevelopmentConfig(Config):
    DEBUG = True
    DEVELOPMENT = True
    SEND_TO_SLACK = True
