# coding=utf-8
import requests_mock
from mock import patch
from monitorrent.db import DBSession
from monitorrent.plugins.trackers import LoginResult, TrackerSettings
from monitorrent.plugins.trackers.nnmclub import NnmClubPlugin, NnmClubTopic, NnmClubCredentials, \
    NnmClubLoginFailedException
from tests import DbTestCase, use_vcr
from tests.plugins.trackers.tests_nnmclub.nnmclub_helper import NnmClubTrackerHelper, \
    LOGIN_FORM, TURNSTILE, WRONG_PASSWORD_PAGE

#helper = NnmClubTrackerHelper.login('login@gmail.com', 'p@$$w0rd')
helper = NnmClubTrackerHelper()


class NnmClubPluginTest(DbTestCase):
    def setUp(self):
        super(NnmClubPluginTest, self).setUp()
        plugin_settings = TrackerSettings(10, None)
        self.plugin = NnmClubPlugin()
        self.plugin.init(plugin_settings)
        self.urls_to_check = [
            u"http://nnmclub.to/forum/viewtopic.php?t=409969",
            u"http://nnmclub.to/forum/viewtopic.php?t=409969"
        ]

    def test_can_parse_url(self):
        for url in self.urls_to_check:
            self.assertTrue(self.plugin.can_parse_url(url))

        bad_urls = [
            u"http://nnmclub.ty/forum/viewtopic.php?t=1",
            u"http://not-nnmclub.to/forum/viewtopic.php?t=409969"
        ]
        for url in bad_urls:
            self.assertFalse(self.plugin.can_parse_url(url))

    @use_vcr
    def test_parse_url(self):
        parsed_url = self.plugin.parse_url(self.urls_to_check[0])
        self.assertEqual(parsed_url[u'original_name'], u'Легенда о Тиле (1976) DVDRip')

    @use_vcr
    def test_parse_not_found_url(self):
        parsed_url = self.plugin.parse_url(u'https://nnmclub.to/forum/viewtopic.php?t=1')
        self.assertIsNone(parsed_url)

    def test_login_verify(self):
        self.assertFalse(self.plugin.verify())
        self.assertEqual(self.plugin.login(), LoginResult.CredentialsNotSpecified)

        credentials = {u'username': u'', u'password': u''}
        self.assertEqual(self.plugin.update_credentials(credentials), LoginResult.CredentialsNotSpecified)
        self.assertFalse(self.plugin.verify())

        with requests_mock.Mocker() as mocker:
            mocker.get(u'https://nnmclub.to/forum/login.php', text=LOGIN_FORM.format(captcha=u''))
            mocker.post(u'https://nnmclub.to/forum/login.php', text=WRONG_PASSWORD_PAGE)

            credentials = {u'username': helper.fake_username, u'password': helper.fake_password}
            self.assertEqual(self.plugin.update_credentials(credentials), LoginResult.IncorrentLoginPassword)
            self.assertFalse(self.plugin.verify())

    def test_login_stores_session_of_the_tracker(self):
        sid = u'0123456789abcdef0123456789abcdef'
        profile_url = u'https://nnmclub.to/forum/profile.php?mode=viewprofile&u=9876543'

        def login(username, password):
            self.plugin.tracker.setup(u'9876543', sid)

        with patch.object(self.plugin.tracker, u'login', side_effect=login):
            with requests_mock.Mocker() as mocker:
                mocker.get(profile_url, text=u'profile')

                credentials = {u'username': helper.real_username, u'password': helper.real_password}
                self.assertEqual(self.plugin.update_credentials(credentials), LoginResult.Ok)
                self.assertTrue(self.plugin.verify())

        with DBSession() as db:
            cred = db.query(NnmClubCredentials).first()
            self.assertEqual(cred.sid, sid)
            self.assertEqual(cred.user_id, u'9876543')

    def test_login_with_captcha_on_login_form(self):
        with requests_mock.Mocker() as mocker:
            mocker.get(u'https://nnmclub.to/forum/login.php', text=LOGIN_FORM.format(captcha=TURNSTILE))

            credentials = {u'username': helper.fake_username, u'password': helper.fake_password}
            self.assertEqual(self.plugin.update_credentials(credentials), LoginResult.CaptchaRequired)

    def test_login_with_session_from_browser(self):
        """
        While login.php is behind a CAPTCHA the session cookie copied from a browser is the only way in
        """
        sid = u'0123456789abcdef0123456789abcdef'
        with requests_mock.Mocker() as mocker:
            mocker.get(u'https://nnmclub.to/forum/index.php',
                       text=u'<a href="login.php?logout=true&amp;sid=' + sid + u'">Exit</a>')

            credentials = {u'username': u'', u'password': u'', u'sid': sid}
            self.assertEqual(self.plugin.update_credentials(credentials), LoginResult.Ok)
            self.assertTrue(self.plugin.verify())

    def test_update_credentials_keeps_stored_session(self):
        sid = u'0123456789abcdef0123456789abcdef'
        with requests_mock.Mocker() as mocker:
            mocker.get(u'https://nnmclub.to/forum/index.php',
                       text=u'<a href="login.php?logout=true&amp;sid=' + sid + u'">Exit</a>')

            self.plugin.update_credentials({u'username': u'', u'password': u'', u'sid': sid})
            # empty session fields must not drop a working session
            self.plugin.update_credentials({u'username': u'user', u'password': u'pass',
                                            u'sid': u'  ', u'autologin_data': u''})

        with DBSession() as db:
            self.assertEqual(db.query(NnmClubCredentials).first().sid, sid)

    def test_login_with_autologin_cookie(self):
        """
        The autologin cookie alone is enough: phpBB builds a session out of it and the plugin
        stores the sid it gets back
        """
        data = u'a%3A1%3A%7Bs%3A6%3A%22userid%22%3Bs%3A7%3A%229876543%22%3B%7D'
        issued = u'f' * 32
        profile_url = u'https://nnmclub.to/forum/profile.php?mode=viewprofile&u=9876543'

        with requests_mock.Mocker() as mocker:
            mocker.get(profile_url, text=u'profile', cookies={u'phpbb2mysql_4_sid': issued})

            credentials = {u'username': u'', u'password': u'', u'autologin_data': data}
            self.assertEqual(self.plugin.update_credentials(credentials), LoginResult.Ok)

        with DBSession() as db:
            cred = db.query(NnmClubCredentials).first()
            self.assertEqual(cred.sid, issued)
            self.assertEqual(cred.user_id, u'9876543')
            self.assertEqual(cred.autologin_data, data)

    def test_verify_stores_a_renewed_session(self):
        data = u'a%3A1%3A%7Bs%3A6%3A%22userid%22%3Bs%3A7%3A%229876543%22%3B%7D'
        renewed = u'e' * 32
        profile_url = u'https://nnmclub.to/forum/profile.php?mode=viewprofile&u=9876543'

        with requests_mock.Mocker() as mocker:
            mocker.get(profile_url, text=u'profile')
            self.plugin.update_credentials({u'username': u'', u'password': u'',
                                            u'sid': u'expired', u'autologin_data': data})

        with requests_mock.Mocker() as mocker:
            mocker.get(profile_url, text=u'profile', cookies={u'phpbb2mysql_4_sid': renewed})
            self.assertTrue(self.plugin.verify())

        with DBSession() as db:
            # the sid nnmclub handed out replaces the expired one without any user action
            self.assertEqual(db.query(NnmClubCredentials).first().sid, renewed)

    def test_login_failed_exceptions_1(self):
        # noinspection PyUnresolvedReferences
        with patch.object(self.plugin.tracker, u'login',
                          side_effect=NnmClubLoginFailedException(
                              NnmClubLoginFailedException.CODE_INVALID_LOGIN_PASSWORD,
                              u'Invalid login or password')):
            credentials = {u'username': helper.real_username, u'password': helper.real_password}
            self.assertEqual(self.plugin.update_credentials(credentials), LoginResult.IncorrentLoginPassword)

    def test_login_failed_exceptions_173(self):
        # noinspection PyUnresolvedReferences
        with patch.object(self.plugin.tracker, u'login',
                          side_effect=NnmClubLoginFailedException(173, u'Invalid login or password')):
            credentials = {u'username': helper.real_username, u'password': helper.real_password}
            self.assertEqual(self.plugin.update_credentials(credentials), LoginResult.Unknown)

    def test_login_unexpected_exceptions(self):
        # noinspection PyUnresolvedReferences
        with patch.object(self.plugin.tracker, u'login', side_effect=Exception):
            credentials = {u'username': helper.real_username, u'password': helper.real_password}
            self.assertEqual(self.plugin.update_credentials(credentials), LoginResult.Unknown)

    @use_vcr
    def test_prepare_request(self):
        self.plugin.tracker.sid = helper.real_sid
        url = self.urls_to_check[0]
        request = self.plugin._prepare_request(NnmClubTopic(url=url))
        self.assertIsNotNone(request)
        self.assertEqual(request.url, u'https://nnmclub.to/forum/download.php?id=370059')
