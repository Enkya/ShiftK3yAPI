""" Application MAIN Module """

from flask import Flask, jsonify
from flask_restplus import Api

from api.models import db
try:
    from .config import Configuration
except ImportError:
    from config import configuration

def create_app(environment="Development"):
    """
    Creates an instance of the application with the given environment
    
    Args:
        environment (str): Specify the configuration to initialize the app with

    Returns:
        app(Flask): Returns an instance of Flask as the application

    """
    app = Flask(__name__)
    app.config.from_object(configuration[environment])
    db.init_app(app)

    api = Api(
        app = app,
        default = 'API',
        default_label = "Available Endpoints",
        title = 'ShiftK3yBackend',
        version = '1.0',
        description = """ ShiftK3yBackend Documentation """,
        scheme = 'https'
    )

    @app.errorhandler(404)
    def resource_not_found(error):
        response = jsonify(dict(
            error = 'Not found',
            messge = 'The requested URL was not found on the server'
        ))
        response.status_code = 404
        return response

    @app.errorhandler(500)
    def internal_server_error(error):
        response = jsonify(dict(
            error = 'Internal Server Error',
            message = 'The server encountered an internal error.'
        ))
        response.status_code = 500
        return response

    return app