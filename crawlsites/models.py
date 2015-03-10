# -*- coding: utf-8 -*-

__author__ = 'frank'

from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.dialects import mysql


from datetime import datetime

db = SQLAlchemy()


class GplusUser(db.Model):

    """用户表"""
    __tablename__ = "gplususers"

    id = db.Column(mysql.INTEGER(30), primary_key=True)

    uid = db.Column(db.String(30))
    display_name = db.Column(db.String(100))
    url = db.Column(db.String(100))

    def __repr__(self):
        return 'GplusUser %s' % self.uid


class TwitterUser(db.Model):

    """用户信息表"""
    __tablename__ = 'twitterusers'

    # 其中id用于外键链接，user_id与api交互
    # 针对于mysql数据库
    id = db.Column(mysql.INTEGER(30), primary_key=True)
    # id_str
    user_id = db.Column(db.String(30))
    name = db.Column(db.String(50))
    screen_name = db.Column(db.String(50))
    location = db.Column(db.String(30))
    statuses_count = db.Column(db.Integer)
    followers_count = db.Column(db.Integer)
    # 关注人员数, following
    friends_count = db.Column(db.Integer)
    created_at = db.Column(db.DateTime)
    # 下次待抓取消息id下限
    since_id = db.Column(db.String(30), default='0')
    # 是否为待监控用户
    is_target = db.Column(db.Boolean, default=False)
    # 关注者id，表明该待同步用户被monitor_user_id关注
    monitor_user_id = db.Column(mysql.INTEGER(30))
    # 图像地址
    profile_image_url = db.Column(db.String(150))
    # url 主页地址
    url = db.Column(db.String(150))

    access_tokens = db.relationship(
        'TwitterAccessToken', backref='user', lazy='dynamic', order_by='desc(TwitterAccessToken.created_at)')

    def __repr__(self):
        return 'TwitterUser %s' % self.screen_name


class TwitterAccessToken(db.Model):

    """access_token信息表"""
    __tablename__ = 'twitteraccesstokens'

    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(50))
    access_token_secret = db.Column(db.String(45))
    is_valid = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(mysql.INTEGER(30), db.ForeignKey('twitterusers.id'))

    def __repr__(self):
        return "TwitterAccessToken userid %d" % self.user_id


class User(db.Model):

    """用户表"""
    __tablename__ = "users"

    id = db.Column(mysql.INTEGER(30), primary_key=True)

    uid = db.Column(db.String(30))
    display_name = db.Column(db.String(100))
    url = db.Column(db.String(100))

    activities = db.relationship(
        'Activity', backref='user', lazy='dynamic', order_by='desc(Activity.created_at)')

    def __repr__(self):
        return 'User %s' % self.uid


class Activity(db.Model):

    """状态表"""
    __tablename__ = 'activities'

    id = db.Column(mysql.INTEGER(30), primary_key=True)

    activity_id = db.Column(db.String(50))
    object_type = db.Column(db.String(30))
    content = db.Column(db.TEXT)
    url = db.Column(db.String(100))

    published = db.Column(db.DateTime)
    updated = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime)

    user_id = db.Column(mysql.INTEGER(30), db.ForeignKey('users.id'))

    def __repr__(self):
        return 'Activity %s' % self.activity_id
