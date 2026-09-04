# coding=utf-8
import httpretty
import requests_mock
from monitorrent.plugins.trackers import TrackerSettings
from monitorrent.plugins.trackers.nnmclub import NnmClubTracker, LoginResult, NnmClubLoginFailedException
from unittest import TestCase
from tests import use_vcr
from tests.plugins.trackers.tests_nnmclub.nnmclub_helper import NnmClubTrackerHelper, \
    LOGIN_FORM, TURNSTILE, CAPTCHA_ERROR_PAGE, WRONG_PASSWORD_PAGE

# helper = NnmClubTrackerHelper.login('login@gmail.com', 'p@$$w0rd')
helper = NnmClubTrackerHelper()


class NnmClubTrackerTest(TestCase):
    def setUp(self):
        super(NnmClubTrackerTest, self).setUp()
        self.tracker_settings = TrackerSettings(10, None)
        self.tracker = NnmClubTracker()
        self.tracker.tracker_settings = self.tracker_settings

    def test_can_parse_url(self):
        self.assertTrue(self.tracker.can_parse_url(u'http://nnmclub.to/forum/viewtopic.php?t=409969'))
        self.assertTrue(self.tracker.can_parse_url(u'https://nnmclub.to/forum/viewtopic.php?t=409969'))
        self.assertFalse(self.tracker.can_parse_url(u'http://not-nnmclub.to/forum/viewtopic.php?t=409969'))

    def test_get_url(self):
        expected = u'http://nnmclub.to/forum/viewtopic.php?t=409969'
        self.assertEqual(self.tracker.get_url(u'http://nnmclub.to/forum/viewtopic.php?t=409969'), expected)

    @use_vcr
    def test_parse_url(self):
        original_name = u'Легенда о Тиле (1976) DVDRip'
        urls = [u'http://nnmclub.to/forum/viewtopic.php?t=409969',
                u'https://nnmclub.to/forum/viewtopic.php?t=409969']
        for url in urls:
            result = self.tracker.parse_url(url)
            self.assertIsNotNone(result, u'Can\'t parse url={}'.format(url))
            self.assertTrue(u'original_name' in result, u'Can\'t find original_name for url={}'.format(url))
            self.assertEqual(original_name, result[u'original_name'])

    @use_vcr()
    def test_parse_url_failed(self):
        urls = [u'http://nnmclub.to/forum/viewtopic1.php?t=409969',
                u'http://nnmclub.to/forum/login.php',
                u'http://not-nnm-club/forum/viewtopic.php?t=409969',
                u'http://nnmclub.to/forum/viewtopic.php?t=1']
        for url in urls:
            result = self.tracker.parse_url(url)
            self.assertFalse(result)

    def test_parse_user_id(self):
        # url encoded a:1:{s:6:"userid";s:7:"9876543";}
        data = u'a%3A1%3A%7Bs%3A6%3A%22userid%22%3Bs%3A7%3A%229876543%22%3B%7D'
        self.assertEqual(NnmClubTracker.parse_user_id(data), u'9876543')

    def test_login_posts_the_form_of_the_login_page(self):
        with requests_mock.Mocker() as mocker:
            mocker.get(u'https://nnmclub.to/forum/login.php', text=LOGIN_FORM.format(captcha=u''))
            post = mocker.post(u'https://nnmclub.to/forum/login.php', text=WRONG_PASSWORD_PAGE)

            with self.assertRaises(NnmClubLoginFailedException):
                self.tracker.login(u'\u041f\u0440\u0438\u0432\u0435\u0442', helper.fake_password)

        body = post.last_request.text
        # login.php rejects the form unless the token rendered into it is posted back
        self.assertIn(u'code=56171b2fc24dfd1a', body)
        self.assertIn(u'autologin=on', body)
        # the forum is windows-1251, not utf-8
        self.assertIn(u'username=%CF%F0%E8%E2%E5%F2', body)

    def test_login_without_session_cookie(self):
        with requests_mock.Mocker() as mocker:
            mocker.get(u'https://nnmclub.to/forum/login.php', text=LOGIN_FORM.format(captcha=u''))
            mocker.post(u'https://nnmclub.to/forum/login.php', status_code=302,
                        headers={u'location': u'https://nnmclub.to/forum/index.php'})
            mocker.get(u'https://nnmclub.to/forum/index.php', text=u'ok')

            with self.assertRaises(NnmClubLoginFailedException) as cm:
                self.tracker.login(helper.fake_username, helper.fake_password)

        self.assertEqual(cm.exception.code, NnmClubLoginFailedException.CODE_NO_SESSION_COOKIE)

    def test_fail_login(self):
        with requests_mock.Mocker() as mocker:
            mocker.get(u'https://nnmclub.to/forum/login.php', text=LOGIN_FORM.format(captcha=u''))
            mocker.post(u'https://nnmclub.to/forum/login.php', text=WRONG_PASSWORD_PAGE)

            with self.assertRaises(NnmClubLoginFailedException) as cm:
                self.tracker.login(u"admin@nnmclub.to", u"FAKE_PASSWORD")

        self.assertEqual(cm.exception.code, NnmClubLoginFailedException.CODE_INVALID_LOGIN_PASSWORD)
        self.assertEqual(cm.exception.message, u'Invalid login or password')

    def test_fail_login_captcha_on_form(self):
        with requests_mock.Mocker() as mocker:
            mocker.get(u'https://nnmclub.to/forum/login.php', text=LOGIN_FORM.format(captcha=TURNSTILE))
            post = mocker.post(u'https://nnmclub.to/forum/login.php', text=CAPTCHA_ERROR_PAGE)

            with self.assertRaises(NnmClubLoginFailedException) as cm:
                self.tracker.login(helper.fake_username, helper.fake_password)

        self.assertEqual(cm.exception.code, NnmClubLoginFailedException.CODE_CAPTCHA_REQUIRED)
        # there is no point in sending credentials to a form that is going to reject them
        self.assertFalse(post.called)

    def test_fail_login_captcha_in_response(self):
        with requests_mock.Mocker() as mocker:
            mocker.get(u'https://nnmclub.to/forum/login.php', text=LOGIN_FORM.format(captcha=u''))
            mocker.post(u'https://nnmclub.to/forum/login.php', text=CAPTCHA_ERROR_PAGE)

            with self.assertRaises(NnmClubLoginFailedException) as cm:
                self.tracker.login(helper.fake_username, helper.fake_password)

        self.assertEqual(cm.exception.code, NnmClubLoginFailedException.CODE_CAPTCHA_REQUIRED)

    @helper.use_vcr(inject_cassette=True)
    def test_verify(self, cassette):
        user_id = helper.fake_user_id if len(cassette) > 0 else helper.real_user_id
        sid = helper.fake_sid if len(cassette) > 0 else helper.real_sid
        tracker = NnmClubTracker(user_id, sid)
        tracker.tracker_settings = self.tracker_settings
        self.assertTrue(tracker.verify())

    def test_verify_false(self):
        self.assertFalse(self.tracker.verify())

    def test_verify_without_user_id(self):
        # a session pasted by hand carries no user id, the logout link tells logged in from anonymous
        tracker = NnmClubTracker(sid=u'2' * 32)
        tracker.tracker_settings = self.tracker_settings
        with requests_mock.Mocker() as mocker:
            mocker.get(u'https://nnmclub.to/forum/index.php',
                       text=u'<a href="login.php?logout=true&amp;sid=' + u'2' * 32 + u'">Exit</a>')
            self.assertTrue(tracker.verify())

        with requests_mock.Mocker() as mocker:
            mocker.get(u'https://nnmclub.to/forum/index.php', text=u'<a href="login.php">Login</a>')
            self.assertFalse(tracker.verify())

    @use_vcr()
    def test_verify_fail(self):
        tracker = NnmClubTracker(u"9876543", u'2' * 32)
        tracker.tracker_settings = self.tracker_settings
        self.assertFalse(tracker.verify())

    @use_vcr()
    def test_get_download_url(self):
        urls = [u'http://nnmclub.to/forum/viewtopic.php?t=409969',
                u'https://nnmclub.to/forum/viewtopic.php?t=409969']
        for url in urls:
            result = self.tracker.get_download_url(url)
            self.assertEqual(result, u'https://nnmclub.to/forum/download.php?id=370059')

    @helper.use_vcr(inject_cassette=True)
    def test_get_download_url_with_login(self, cassette):
        # login will update cassette
        has_cassette = len(cassette) > 0
        urls = [u'http://nnmclub.to/forum/viewtopic.php?t=1035515',
                u'https://nnmclub.to/forum/viewtopic.php?t=1035515']
        for url in urls:
            result = self.tracker.get_download_url(url)
            self.assertFalse(result)

        user_id = helper.fake_user_id if has_cassette else helper.real_user_id
        sid = helper.fake_sid if has_cassette else helper.real_sid
        self.tracker.setup(user_id, sid)

        for url in urls:
            result = self.tracker.get_download_url(url)
            self.assertEqual(result, u'https://nnmclub.to/forum/download.php?id=866904')
