# -*- coding: utf-8 -*-

__author__ = 'frank'

from flask import Blueprint, render_template, redirect, session, request, url_for, flash, current_app

from ..forms import UserForm, TwitterUserForm, GplusUserForm
from ..models import db, User, TwitterUser, TwitterAccessToken, GplusUser

import tweepy
from datetime import datetime, timedelta
from functools import wraps
import re
import requests
import urllib

bp = Blueprint('site', __name__)


@bp.route('/')
def index():
    return render_template('site/index.html')
    # return render_template('site/fb.html')


@bp.route('/add_users', methods=['GET', 'POST'])
def add_users():
    form = UserForm()
    if form.validate_on_submit():
        user = User()
        user.uid = form.id.data.strip()
        user.display_name = form.display_name.data.strip()

        #-------------------------
        params = dict(
            query=form.display_name.data.strip(),
            key=current_app.config['CLIENT_SECRET']
        )
        search_people_url = current_app.config[
            'SEARCH_PEOPLE_URI'] + '?' + urllib.urlencode(params)
        print search_people_url
        r = requests.get(search_people_url)
        print r.json()
        items = r.json()['items']
        for item in items:
            if item['id'] == form.id.data.strip():
                user.url = item['url']
                break

        db.session.add(user)
        db.session.commit()
        flash('添加用户成功')
        return redirect(url_for('site.users'))
    return render_template('site/add_users.html', form=form)


@bp.route('/users/', defaults={'page': 1})
@bp.route('/users/<int:page>')
def users(page):
    users = User.query.paginate(
        page,
        current_app.config['USER_PER_PAGE'],
        error_out=True
    )
    return render_template('site/users.html', users=users)


def clear_session():
    session.pop('access_token', None)
    session.pop('access_token_secret', None)
    session.pop('consumer_token', None)
    session.pop('consumer_secret', None)


def save_user_and_token_access():
    """在用户授权时更新用户和access_token信息"""
    auth = tweepy.OAuthHandler(
        session['consumer_token'],
        session['consumer_secret']
    )
    auth.set_access_token(session.get('access_token'),
                          session.get('access_token_secret'))
    api = tweepy.API(auth)
    try:
        me = api.me()
    except Exception, e:
        flash('出错信息： %s' % e)
        flash('调用api.me次数超出规定上限，请15min后重试')
        return redirect(url_for('site.twitter_index'))
    if me:
        # 判断是否已经保存当前进行授权操作的用户
        user = TwitterUser.query.filter_by(user_id=me.id_str).first()
        if user:
            accestoken = TwitterAccessToken.query.filter_by(
                user_id=user.id).filter_by(is_valid=True).first()
            # 如果是否已存在合法access_token（用户可能在主页撤销授权后又重新授权）
            if accestoken:
                if accestoken.access_token != session.get('access_token'):
                    # 保证某指定id用户只有一个合法的access_token
                    accestoken.is_valid = False
                    db.session.add(accestoken)
                    flash('数据表中您的旧access_token已失效')
                else:
                    flash('数据表中已存在您的合法access_token')
                    return
        else:
            user = TwitterUser(user_id=me.id_str, name=me.name, screen_name=me.screen_name,
                               location=me.location, statuses_count=me.statuses_count,
                               followers_count=me.followers_count, friends_count=me.friends_count,
                               created_at=me.created_at, profile_image_url=me.profile_image_url,
                               url=me.url
                               )
            db.session.add(user)
            db.session.commit()
            flash('数据表成功保存您的twitter账户信息')
        new_accesstoken = TwitterAccessToken(user_id=user.id,
                                             access_token=session.get(
                                                 'access_token'),
                                             access_token_secret=session.get(
                                                 'access_token_secret')
                                             )
        db.session.add(new_accesstoken)
        db.session.commit()
        flash('数据表成功保存您的新access_token')
    else:
        flash('调用api.me，数据表保存access_token信息失败')


@bp.route('/twitter_index')
def twitter_index():
    return render_template('site/twitter_index.html', users=users, twitter_selected=True)


@bp.route('/twitter_pre_signin')
def twitter_pre_signin():
    """预登陆，跳转到授权页面"""
    session['consumer_token'] = current_app.config['TWITTER_CONSUMER_TOKEN']
    session['consumer_secret'] = current_app.config['TWITTER_CONSUMER_SECRET']
    auth = tweepy.OAuthHandler(
        session['consumer_token'],
        session['consumer_secret'],
        current_app.config['CALLBACK_URL']
    )
    try:
        redirect_url = auth.get_authorization_url()
    except tweepy.TweepError:
        flash('Error! Failed to get request token, 请重新授权')
        clear_session()
        return redirect(url_for('site.twitter_index', twitter_selected=True))
    session['request_token'] = auth.request_token
    return redirect(redirect_url)


@bp.route('/twitter_signin')
def twitter_signin():
    """登陆"""
    if session.get('consumer_token') and session.get('consumer_secret'):
        auth = tweepy.OAuthHandler(
            session.get('consumer_token'),
            session.get('consumer_secret')
        )
        # request_token用完即删掉
        request_token = session.pop('request_token', None)
        auth.request_token = request_token
        verifier = request.args.get('oauth_verifier')
        try:
            auth.get_access_token(verifier)
        except tweepy.TweepError:
            flash('Error! Failed to get access token, 请重新授权')
            clear_session()
            return redirect(url_for('site.twitter_index', twitter_selected=True))
        session['access_token'] = auth.access_token
        session['access_token_secret'] = auth.access_token_secret

        save_user_and_token_access()
        # update_status()

        flash('登陆并授权成功')
        return redirect(url_for('site.twitter_index', twitter_selected=True))
    else:
        flash('session中无可用consumer_token和consumer_secret，请先授权新用户')
        return redirect(url_for('site.twitter_index', twitter_selected=True))


@bp.route('/twitter_authorized_users/', defaults={'page': 1})
@bp.route('/twitter_authorized_users/<int:page>')
def twitter_authorized_users(page):
    valid_users = TwitterUser.query.join(TwitterAccessToken).filter_by(
        is_valid=True).order_by(TwitterUser.id.desc())
    valid_users = valid_users.paginate(page,
                                       current_app.config['USER_PER_PAGE'],
                                       error_out=True
                                       )
    return render_template('site/twitter_authorized_users.html', valid_users=valid_users, twitter_selected=True)


@bp.route('/twitter_target_users/', defaults={'page': 1})
@bp.route('/twitter_target_users/<int:page>')
def twitter_target_users(page):
    target_users = TwitterUser.query.filter_by(
        is_target=True).order_by(TwitterUser.id.desc())
    target_users = target_users.paginate(page,
                                         current_app.config['USER_PER_PAGE'],
                                         error_out=True
                                         )
    return render_template('site/twitter_target_users.html', target_users=target_users, twitter_selected=True)


@bp.route('/twitter_delete_target_user/', defaults={'user_id': None})
@bp.route('/twitter_delete_target_user/<user_id>', methods=['POST'])
def twitter_delete_target_user(user_id):
    """删除待同步用户
    策略是将该用户is_target设为False，已经抓取的推文不做处理
    但考虑到api.home_timeline抓取上限，同时需要解除关注关系
    """
    user = TwitterUser.query.filter_by(
        is_target=True).filter_by(user_id=user_id).first()
    if user:
        user.is_target = False
        db.session.add(user)
        db.session.commit()
        # 此处只改变is_target，取消关注在定时任务里做
        flash('screen_name为' + user.screen_name +
              '的用户被成功删除，取消关注但仍保留已抓取的与其相关的推文')
    else:
        flash('删除用户失败')
    return redirect(url_for('site.twitter_target_users', twitter_selected=True))


@bp.route('/twitter_add_users', methods=['GET', 'POST'])
def twitter_add_users():
    """添加待同步用户"""
    auth = tweepy.OAuthHandler(
        current_app.config['TWITTER_CONSUMER_TOKEN'],
        current_app.config['TWITTER_CONSUMER_SECRET']
    )
    # screen_name唯一
    form = TwitterUserForm()
    if form.validate_on_submit():
        # 一个有合法access_token账户添加目标用户
        accesstokens = TwitterAccessToken.query.filter_by(is_valid=True).all()
        if not accesstokens:
            flash('数据表中无可用access_token，请用任意账户登陆授权')
            return redirect(url_for('site.twitter_pre_signin', twitter_selected=True))
        # 且考虑用户添加待同步目标上限为1000
        accesstoken = None
        for an in accesstokens:
            if an.user.followers_count < current_app.config['MAX_FOLLOWERS_COUNT']:
                accesstoken = an
                break
        if not accesstoken:
            flash('所有用户各自添加待同步用户数超过上限，请用任意新账户登陆授权')
            return redirect(url_for('site.twitter_pre_signin', twitter_selected=True))

        auth.set_access_token(
            accesstoken.access_token, accesstoken.access_token_secret)
        api = tweepy.API(auth)

        names = [form.screen_name1.data.strip(),
                 form.screen_name2.data.strip(),
                 form.screen_name3.data.strip(),
                 form.screen_name4.data.strip(),
                 form.screen_name5.data.strip()
                 ]
        hasName = False
        for name in names:
            if name:
                user = TwitterUser.query.filter_by(screen_name=name).first()
                if not user:
                    try:
                        target_user = api.get_user(name)
                    except Exception, e:
                        flash('出错信息： %s' % e)
                        flash('调用api.get_user，没有找到screen_name为' + name + '的人')
                        return redirect(url_for('site.index', twitter_selected=True))
                    else:
                        user = TwitterUser(user_id=target_user.id_str,
                                           name=target_user.name,
                                           screen_name=target_user.screen_name,
                                           location=target_user.location,
                                           statuses_count=target_user.statuses_count,
                                           followers_count=target_user.followers_count,
                                           friends_count=target_user.friends_count,
                                           created_at=target_user.created_at,
                                           monitor_user_id=accesstoken.user.id,
                                           is_target=True, url=target_user.url,
                                           profile_image_url=target_user.profile_image_url,
                                           )
                        # 有合法access_token的用户尚未关注该目标用户则直接关注
                        # 不需考虑其他有合法access_token账户可能已经关注该用户，造成status重复
                        # 因为is_target字段就是判断是否是目标用户进行去重的
                        if not target_user.id in api.friends_ids(accesstoken.user.user_id):
                            api.create_friendship(target_user.id)
                        else:
                            flash(
                                name + '已经被screen_name为' +
                                accesstoken.user.screen_name + '的人关注'
                            )
                        # 两种情况都需要添加该目标用户
                        # 将该用户添加为待同步用户，从home_timeline中只取目标用户的tweet
                        flash(accesstoken.user.screen_name + '成功添加新的待同步用户')
                        db.session.add(user)
                else:  # 已经在user表中
                    if user.monitor_user_id:
                        # 删除时将该字段设为false，此时需检查该字段
                        if user.is_target:
                            monitor_user = TwitterUser.query.filter_by(
                                id=user.monitor_user_id).first()
                            flash(
                                name + '已经被screen_name为' + monitor_user.screen_name + '的人关注')
                        else:
                            # 重新添加已删除用户为待同步用户
                            # 改变is_target，并且需关注
                            user.is_target = True
                            db.session.add(user)
                            flash(name + '已经在user表中，原来被删除现在重新激活该用户')
                            api.create_friendship(user.user_id)
                            flash(
                                accesstoken.user.screen_name + '重新关注' + user.screen_name)
                    else:
                        flash(screen_name + '已经在user表中，再添加些新用户吧')
                hasName = True
        db.session.commit()
        if not hasName:
            flash('至少添加一些再提交吧')
            return render_template('site/twitter_add_users.html', form=form, twitter_selected=True)
        return redirect(url_for('site.twitter_target_users', twitter_selected=True))
    return render_template('site/twitter_add_users.html', form=form, twitter_selected=True)


from oauth2client import client
from googleapiclient import sample_tools


@bp.route('/gplus_signin')
def gplus_signin():
    """登陆"""
    # Authenticate and construct service.
    service, flags = sample_tools.init(
        '', 'plus', 'v1', __doc__, __file__,
        scope='https://www.googleapis.com/auth/plus.me')
    try:
        person = service.people().get(userId='me').execute()
        flash('授权用户名: %s' % person['displayName'])
        flash('登陆并授权成功, credentials信息被保存在crawlsited/plus.dat')
        return redirect(url_for('site.gplus_index', gplus_selected=True))
    except client.AccessTokenRefreshError:
        flash('The credentials have been revoked or expired, please re-run'
              'the application to re-authorize.')
        return redirect(url_for('site.gplus_index', gplus_selected=True))


@bp.route('/gplus_add_user', methods=['GET', 'POST'])
def gplus_add_user():
    form = GplusUserForm()
    if form.validate_on_submit():
        display_name = form.display_name.data.strip()
        id = form.id.data.strip()
        user = GplusUser()

        # Authenticate and construct service.
        service, flags = sample_tools.init(
            '', 'plus', 'v1', __doc__, __file__,
            scope='https://www.googleapis.com/auth/plus.me')
        # 添加规则
        # id有值则按照id查询api，保存对应人员信息，忽略用户名
        # id若没值则按照display_name查询api，保存第一条人员信息，并检查是否已经保存此display_name对应id的用户
        if id:
            try:
                person = service.people().get(userId=id).execute()
                user.uid = person['id']
                user.display_name = person['displayName']
                user.url = person['url']
                db.session.add(user)
                db.session.commit()
                flash('成功添加用户<displayName=%s>' % person['displayName'])
            except Exception:
                flash('未查询到<id=%s>的用户' % id)
        else:
            try:
                rets = service.people().search(query=display_name).execute()
                items = rets['items']
                if items:
                    # 此处直接取返回查询结果的第一条
                    person = items[0]
                    # 检查是否重复添加
                    if not GplusUser.query.filter_by(uid=person['id']).first():
                        user.uid = person['id']
                        user.display_name = person['displayName']
                        user.url = person['url']
                        db.session.add(user)
                        db.session.commit()
                        if display_name != person['displayName']:
                            flash('未查询到<display_name=%s>的用户,添加用户<displayName=%s>' % (
                                display_name, person['displayName']))
                        else:
                            flash('成功添加用户<displayName=%s>' %
                                  person['displayName'])
                    else:
                        flash('数据表中已存在<display_name=%s>的用户' % display_name)
                else:
                    flash('未查询到<display_name=%s>的用户' % display_name)
            except Exception:
                flash('未查询到<display_name=%s>的用户' % display_name)
        form.id.data = ""
        form.id.display_name = ""
        return redirect(url_for('site.gplus_target_users'))
    return render_template('site/gplus_add_user.html', form=form, gplus_selected=True)


@bp.route('/gplus_target_users/', defaults={'page': 1})
@bp.route('/gplus_target_users/<int:page>')
def gplus_target_users(page):
    target_users = GplusUser.query.order_by(GplusUser.id.desc())
    target_users = target_users.paginate(page,
                                         current_app.config['USER_PER_PAGE'],
                                         error_out=True
                                         )
    return render_template('site/gplus_target_users.html', target_users=target_users, gplus_selected=True)


@bp.route('/gplus_index')
def gplus_index():
    return render_template('site/gplus_index.html', users=users, gplus_selected=True)


@bp.route('/fb_index')
def fb_index():
    return render_template('site/fb_index.html', users=users, fb_selected=True)
