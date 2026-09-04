# -*- coding: utf-8 -*-
from future import standard_library
standard_library.install_aliases()
from builtins import object
import sys
import six
from requests import Session
import requests
import urllib.request, urllib.parse, urllib.error
from sqlalchemy import Column, Integer, String, ForeignKey
from monitorrent.db import Base, DBSession
from monitorrent.plugins import Topic
from monitorrent.plugin_managers import register_plugin
from monitorrent.utils.soup import get_soup
from monitorrent.utils.bittorrent_ex import Torrent
from monitorrent.plugins.trackers import TrackerPluginBase, WithCredentialsMixin, ExecuteWithHashChangeMixin, LoginResult
from urllib.parse import urlparse, unquote, quote_plus
from phpserialize import loads
import structlog

PLUGIN_NAME = 'nnmclub.to'

log = structlog.get_logger()


class NnmClubCredentials(Base):
    __tablename__ = "nnmclub_credentials"

    username = Column(String, primary_key=True)
    password = Column(String, primary_key=True)
    user_id = Column(String, nullable=True)
    sid = Column(String, nullable=True)


class NnmClubTopic(Topic):
    __tablename__ = "nnmclub_topics"

    id = Column(Integer, ForeignKey('topics.id'), primary_key=True)
    hash = Column(String, nullable=True)

    __mapper_args__ = {
        'polymorphic_identity': PLUGIN_NAME
    }


class NnmClubLoginFailedException(Exception):
    CODE_INVALID_LOGIN_PASSWORD = 1
    CODE_CAPTCHA_REQUIRED = 2
    CODE_NO_SESSION_COOKIE = 3

    def __init__(self, code, message):
        self.code = code
        self.message = message


class NnmClubTracker(object):
    tracker_settings = None
    tracker_domains = [u'nnmclub.to']
    title_headers = [u'torrent :: nnm-club', ' :: nnm-club']
    _login_url = u'https://nnmclub.to/forum/login.php'
    _index_url = u'https://nnmclub.to/forum/index.php'
    _profile_page = u"https://nnmclub.to/forum/profile.php?mode=viewprofile&u={}"
    # every page of the forum is served as windows-1251, forms have to be posted in the same encoding
    _encoding = 'windows-1251'
    # login.php answers with this when the CAPTCHA token is missing or invalid
    _captcha_error = u'неверный код подтверждения'
    _captcha_classes = ['cf-turnstile', 'g-recaptcha']

    def __init__(self, user_id=None, sid=None):
        self.user_id = user_id
        self.sid = sid

    def setup(self, user_id=None, sid=None):
        self.user_id = user_id
        self.sid = sid

    def can_parse_url(self, url):
        parsed_url = urlparse(url)
        return any([parsed_url.netloc == tracker_domain for tracker_domain in self.tracker_domains])

    def parse_url(self, url):
        url = self.get_url(url)
        if not url or not self.can_parse_url(url):
            return None
        parsed_url = urlparse(url)
        if not parsed_url.path == '/forum/viewtopic.php':
            return None

        r = requests.get(url, allow_redirects=False, **self.tracker_settings.get_requests_kwargs())
        if r.status_code != 200:
            return None
        soup = get_soup(r.text)
        title = soup.title.string.strip()
        for title_header in self.title_headers:
            if title.lower().endswith(title_header):
                title = title[:-len(title_header)].strip()
                break

        return self._get_title(title)

    def login(self, username, password):
        s = Session()
        # login.php validates a per-form token and may guard the form with a CAPTCHA,
        # so the form has to be fetched before it can be submitted
        login_page = s.get(self._login_url, **self.tracker_settings.get_requests_kwargs())
        login_form = self._get_login_form(login_page.text)

        if self._has_captcha(login_form):
            raise NnmClubLoginFailedException(NnmClubLoginFailedException.CODE_CAPTCHA_REQUIRED,
                                              "Login form is protected by CAPTCHA")

        data = {u'username': username, u'password': password, u'autologin': u'on',
                u'redirect': u'', u'login': u'1'}
        code = self._get_input_value(login_form, u'code')
        if code is not None:
            data[u'code'] = code

        login_result = s.post(self._login_url, data=self._encode_form(data),
                              headers={'Content-Type': 'application/x-www-form-urlencoded'},
                              **self.tracker_settings.get_requests_kwargs())
        if login_result.url.startswith(self._login_url):
            if self._captcha_error in login_result.text.lower():
                raise NnmClubLoginFailedException(NnmClubLoginFailedException.CODE_CAPTCHA_REQUIRED,
                                                  "Login form is protected by CAPTCHA")
            raise NnmClubLoginFailedException(NnmClubLoginFailedException.CODE_INVALID_LOGIN_PASSWORD,
                                              "Invalid login or password")
        if u'phpbb2mysql_4_sid' not in s.cookies:
            raise NnmClubLoginFailedException(NnmClubLoginFailedException.CODE_NO_SESSION_COOKIE,
                                              "Login page didn't set a session cookie")
        self.sid = s.cookies[u'phpbb2mysql_4_sid']
        self.user_id = self.parse_user_id(s.cookies[u'phpbb2mysql_4_data'])

    def verify(self):
        cookies = self.get_cookies()
        if not cookies:
            return False
        if self.user_id:
            profile_page_url = self._profile_page.format(self.user_id)
            profile_page_result = requests.get(profile_page_url, cookies=cookies,
                                               **self.tracker_settings.get_requests_kwargs())
            return profile_page_result.url == profile_page_url
        # the session was set up by hand and the user id is unknown:
        # the logout link is only rendered for a logged in user
        index_page_result = requests.get(self._index_url, cookies=cookies,
                                         **self.tracker_settings.get_requests_kwargs())
        return u'logout=true' in index_page_result.text

    @staticmethod
    def parse_user_id(data_cookie):
        """
        Extracts the user id from the serialized phpbb2mysql_4_data cookie

        :rtype: str
        """
        parsed_data = loads(unquote(data_cookie).encode('utf-8'))
        return parsed_data[u'userid'.encode('utf-8')].decode('utf-8')

    @staticmethod
    def _get_login_form(login_page_text):
        soup = get_soup(login_page_text)
        return soup.find('form', id='loginFrm') or soup

    @classmethod
    def _has_captcha(cls, login_form):
        return any(login_form.find(attrs={'class': captcha_class}) is not None
                   for captcha_class in cls._captcha_classes)

    @staticmethod
    def _get_input_value(login_form, name):
        field = login_form.find('input', attrs={'name': name})
        return field.get('value') if field is not None else None

    @classmethod
    def _encode_form(cls, data):
        return '&'.join('{0}={1}'.format(quote_plus(six.text_type(k).encode(cls._encoding)),
                                         quote_plus(six.text_type(v).encode(cls._encoding)))
                        for k, v in data.items())

    def get_cookies(self):
        if not self.sid:
            return False
        return {'phpbb2mysql_4_sid': self.sid, 'ssl': 'enable_ssl'}

    def get_download_url(self, url):
        cookies = self.get_cookies()
        page = requests.get(url, cookies=cookies, **self.tracker_settings.get_requests_kwargs())
        page_soup = get_soup(page.text, 'html5lib' if sys.platform == 'win32' else None)
        anchors = page_soup.find_all("a")
        da = list(filter(lambda tag: tag.has_attr('href') and tag.attrs['href'].startswith("download.php?id="),
                         anchors))
        # not a free torrent
        if len(da) == 0:
            return None
        download_url = 'https://' + self.tracker_domains[0] + '/forum/' + da[0].attrs['href']
        return download_url

    def get_url(self, url):
        if not self.can_parse_url(url):
            return False
        parsed_url = urlparse(url)
        parsed_url = parsed_url._replace(netloc=self.tracker_domains[0])
        return parsed_url.geturl()

    @staticmethod
    def _get_title(title):
        return {'original_name': title}


class NnmClubPlugin(WithCredentialsMixin, ExecuteWithHashChangeMixin, TrackerPluginBase):
    tracker = NnmClubTracker()
    topic_class = NnmClubTopic
    credentials_class = NnmClubCredentials
    credentials_public_fields = ['username', 'sid']
    credentials_private_fields = ['username', 'password', 'user_id', 'sid']
    credentials_form = [{
        'type': 'row',
        'content': [{
            'type': 'text',
            'model': 'username',
            'label': 'Username',
            'flex': 50
        }, {
            "type": "password",
            "model": "password",
            "label": "Password",
            "flex": 50
        }]
    }, {
        'type': 'row',
        'content': [{
            'type': 'text',
            'model': 'sid',
            'label': 'Session id (phpbb2mysql_4_sid cookie, needed while login is behind a CAPTCHA)',
            'flex': 100
        }]
    }]
    topic_form = [{
        'type': 'row',
        'content': [{
            'type': 'text',
            'model': 'display_name',
            'label': 'Name',
            'flex': 100
        }]
    }]

    def update_credentials(self, credentials):
        credentials = dict(credentials)
        sid = credentials.get('sid')
        if sid is not None:
            sid = sid.strip()
            if not sid:
                # an empty field means "keep what is stored", don't drop a working session
                del credentials['sid']
            else:
                credentials['sid'] = sid
        if 'sid' in credentials:
            with DBSession() as db:
                cred = db.query(self.credentials_class).first()
                if cred is None or cred.sid != credentials['sid']:
                    # a session pasted by hand may belong to another account, the stored user id
                    # no longer applies to it
                    credentials['user_id'] = None
        return super(NnmClubPlugin, self).update_credentials(credentials)

    def login(self):
        with DBSession() as db:
            cred = db.query(self.credentials_class).first()
            if not cred:
                return LoginResult.CredentialsNotSpecified
            username = cred.username
            password = cred.password
            user_id = cred.user_id
            sid = cred.sid

        # a session copied from the browser wins over username/password: while login.php
        # is protected by a CAPTCHA it is the only way to get a working session
        if sid:
            self.tracker.setup(user_id, sid)
            if self.tracker.verify():
                return LoginResult.Ok

        if not username or not password:
            return LoginResult.CredentialsNotSpecified

        try:
            self.tracker.login(username, password)
            with DBSession() as db:
                cred = db.query(self.credentials_class).first()
                cred.user_id = self.tracker.user_id
                cred.sid = self.tracker.sid
            return LoginResult.Ok
        except NnmClubLoginFailedException as e:
            if e.code == NnmClubLoginFailedException.CODE_INVALID_LOGIN_PASSWORD:
                return LoginResult.IncorrentLoginPassword
            if e.code == NnmClubLoginFailedException.CODE_CAPTCHA_REQUIRED:
                return LoginResult.CaptchaRequired
            return LoginResult.Unknown
        except Exception as e:
            log.error("Unexpected error while login to nnmclub.to", exception=str(e))
            return LoginResult.Unknown

    def verify(self):
        with DBSession() as db:
            cred = db.query(self.credentials_class).first()
            if not cred or not cred.sid:
                return False
            self.tracker.setup(cred.user_id, cred.sid)
        return self.tracker.verify()

    def can_parse_url(self, url):
        return self.tracker.can_parse_url(url)

    def parse_url(self, url):
        return self.tracker.parse_url(url)

    def _prepare_request(self, topic):
        cookies = self.tracker.get_cookies()
        request = requests.Request('GET', self.tracker.get_download_url(topic.url), cookies=cookies)
        return request.prepare()


register_plugin('tracker', PLUGIN_NAME, NnmClubPlugin())
