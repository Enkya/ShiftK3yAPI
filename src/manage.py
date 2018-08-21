""" Entry point for the Application """

import os
import sys
import click

from flask_migrate import Migrate

from app import create_app
from api.models import db, Role, User

app = create_app(environment=os.environ.get('APP_SETTINGS', 'Development'))
migrate = Migrate(app, db)

@app.shell_context_processor
def make_shell_context():
    return dict(app=app, db=db)

@app.cli.command()
@click.option(
            '--coverage/--no-coverage', 
            default=False,
            help='Enable code coverage')
def test(coverage):
    """ Run the unit tests """
    print('success')
    pass

@app.cli.command()
def create_database():
    """ Create database tables from sqlalchemy models """
    try:
        db.create_all()
        print('Created tables successfully!')
    except Exception:
        print('Failed to create db. Make sure your database server is running')
        

@app.cli.command()
def drop_database():
    """ Drop database tables """
    if click.confirm("Are you sure you want to lose all your data?", default=False):
        try:
            db.drop_all()
            print("Dropped all tables successfully")
        except Exception:
            print("Failed, make sure your db server is running")


@app.cli.command()
def seed():
    """ Seed database tables with initial data """
    pass

