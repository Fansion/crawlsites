# -*- coding: utf-8 -*-

__author__ = 'frank'

from flask.ext.wtf import Form
from wtforms import StringField, TextField, ValidationError
from models import User, GplusUser


class UserForm(Form):

    """添加待同步用户"""

    id = TextField('ID', description='准确的id')
    display_name = TextField('DISPLAY_NAME', description='准确的display_name')

    def validate_id(self, field):
        if User.query.filter_by(uid=field.data).first():
            raise ValidationError('该id对应的用户已经被添加过')


class TwitterUserForm(Form):

    """添加待同步用户"""

    screen_name1 = TextField('ID1', description='准确的twitter screen_name')
    screen_name2 = TextField('ID2', description='准确的twitter screen_name')
    screen_name3 = TextField('ID3', description='准确的twitter screen_name')
    screen_name4 = TextField('ID4', description='准确的twitter screen_name')
    screen_name5 = TextField('ID5', description='准确的twitter screen_name')


class GplusUserForm(Form):

    """添加待同步用户"""

    id = TextField('ID', description='准确的id（选填）')
    display_name = TextField('DISPLAY_NAME', description='准确的display_name(必填)')

    def validate_display_name(self, field):
        if not field.data.strip():
            raise ValidationError('display_name为必填项')

    def validate_id(self, field):
        if GplusUser.query.filter_by(uid=field.data.strip()).first():
            raise ValidationError('该id对应的用户已经被添加过')
