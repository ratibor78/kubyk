class Config(object):
    SQLALCHEMY_DATABASE_URI = 'sqlite:///../sqlite/database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class ProductionConfig(Config):
    DEBUG = False
    DEVELOPMENT = False


class DevelopmentConfig(Config):
    DEBUG = True
    DEVELOPMENT = True
