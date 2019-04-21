import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    FLASKY_MAIL_SUBJECT_PREFIX = '[Flasky]'
    FLASKY_MAIL_SENDER = '1602516156@qq.com'
    FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN')
    MAIL_SERVER = 'smtp.qq.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    CKEDITOR_SERVE_LOCAL = True
    THEMES = {'darkly': 'Darkly', 'sandstone': 'Sandstone', 'united': 'United'}
    FLASKY_SLOW_DB_QUERY_TIME = 0.5
    SQLALCHEMY_RECORD_QUERIES = True

    FLASKY_UPLOAD_PATH = os.path.join(basedir, 'uploads')

    AVATARS_SAVE_PATH = os.path.join(FLASKY_UPLOAD_PATH, 'avatars')
    AVATARS_SIZE_TUPLE = (30, 100, 200)

    MAX_CONTENT_LENGTH = 3 * 1024 * 1024

    WHOOSHEE_MIN_STRING_LEN = 1

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///' + os.path.join(basedir,
                                                                                                'data-dev.db')


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or 'sqlite:///' + os.path.join(basedir,
                                                                                                 'data-test.db')


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'data.db')
    SQLALCHEMY_POOL_RECYCLE = 280

    @classmethod
    def register_logging(self, app):
        import logging
        from logging.handlers import RotatingFileHandler, SMTPHandler
        import os
        from flask import request

        class RequestFormatter(logging.Formatter):

            def format(self, record):
                record.url = request.url
                record.remote_addr = request.remote_addr
                return super(RequestFormatter, self).format(record)

        request_formatter = RequestFormatter(
            '[%(asctime)s] %(remote_addr)s requested %(url)s\n'
            '%(levelname)s in %(module)s: %(message)s'
        )

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        file_handler = RotatingFileHandler(os.path.join(basedir, 'logs/bluelog.log'),
                                           maxBytes=10 * 1024 * 1024, backupCount=10)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)

        mail_handler = SMTPHandler(
            mailhost=app.config['MAIL_SERVER'],
            fromaddr=app.config['MAIL_USERNAME'],
            toaddrs=['ADMIN_EMAIL'],
            subject='Bluelog Application Error',
            credentials=(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD']))
        mail_handler.setLevel(logging.ERROR)
        mail_handler.setFormatter(request_formatter)

        if not app.debug:
            app.logger.addHandler(mail_handler)
            app.logger.addHandler(file_handler)


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
