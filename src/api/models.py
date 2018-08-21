""" Models base. Contains utility methods and properties """
import uuid
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()


def generate_uuid():
    """ Generate unique string """
    return str(uuid.uuid1())

def camel_case(snake_str):
    """ Convert string to camel case """
    title_str = snake_str.title().replace("_", "")
    return title_str[0].lower() + title_str[1:]

class Base(db.Model):
    """ Base model """
    __abstract__ = True
    uuid = db.Column(db.String, primary_key=True, default=generate_uuid)
    name = db.Column(db.String)
    photo = db.Column(db.String)
    description = db.Column(db.String)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    modified_at = db.Column(
                            db.DateTime,
                            default=datetime.utcnow, 
                            onupdate=db.func.current_timestamp()
                        )
    active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        """ Repl representation of models """
        return f"{type(self).__name__}(id='{self.uuid}', name='{self.name}')"
        
    def __str__(self):
        """ Returns string representation of object """
        return self.name
    
    def save(self):
        """
        Save the object in DB

        Returns:
            saved(boolean) true if saved, false otherwise
        """
        try:
            db.session.add(self)
            db.session.commit()
            return True
        except SQLAlchemyError:
            db.session.rollback()
            return False
    
    def delete(self):
        """
        Delete the object in DB.

        Returns:
            deleted(boolean) True if deleted else False
        """
        deleted = None
        try:
            db.session.delete(self)
            db.session.commit()
            deleted = True
        except Exception:
            deleted = False
            db.session.rollback()
        return deleted

    def deactivate(self):
        """
        Deactivate the object in the DB

        Returns:
            deactivated(boolean) True if deactivated else False
        """
        try:
            self.active = False
            self.save()
            return True
        except Exception:
            db.session.rollback()
            return False

    def serialize(self):
        """
        Map model to a dictionary representation
        
        Returns:
            A dict object
        """
        dictionary_mapping = {
            camel_case(attribute.name): str(getattr(self, attribute.name))
            for attribute in self.__table__.columns
        }
        return dictionary_mapping

class Role(Base):
    """Models Roles to which all employees have."""

    __tablename__ = 'roles'
    users = db.relationship('User', secondary='user_role', lazy='dynamic',
                            backref=db.backref('roles', lazy='dynamic'))

class User(Base):
    """ User Model """
    __tablename__ = 'users'
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String)

    @property
    def password(self):
        return 'Password: Write Only'

    @password.setter
    def password(self, password):
        """ Generate password hash """
        self._password_hash = bcrypt.generate_password_hash(
            password, 4
        ).decode('utf-8')

    def verify_password(self, password):
        """ Check if the provided password matches the user password """
        return bcrypt.check_password_hash(self._password_hash, password)