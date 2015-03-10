# -*- coding: utf-8 -*-

__author__ = 'frank'

from flask.ext.script import Manager, Shell
from flask.ext.migrate import Migrate, MigrateCommand
from crawlsites import app
from crawlsites.models import db

manager = Manager(app)

migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)


def make_context():
    return dict(app=app, db=db, Application=Application, User=User, AccessToken=AccessToken, Status=Status)
manager.add_command('shell', Shell(make_context=make_context))


@manager.command
def run():
    # app.run(debug=True, port=5001)
    app.run(host='0.0.0.0', debug=True)

if __name__ == '__main__':
    manager.run()
