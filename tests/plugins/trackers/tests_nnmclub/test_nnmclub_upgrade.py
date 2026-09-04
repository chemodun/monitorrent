# coding=utf-8
from monitorrent.plugins.trackers.nnmclub import upgrade, get_current_version
from sqlalchemy import Column, Integer, String, MetaData, Table, ForeignKey
from tests import UpgradeTestCase
from monitorrent.plugins.trackers import Topic


class NnmClubTrackerUpgradeTest(UpgradeTestCase):
    m0 = MetaData()
    NnmClubCredentials0 = Table("nnmclub_credentials", m0,
                                Column('username', String, primary_key=True),
                                Column('password', String, primary_key=True),
                                Column('user_id', String, nullable=True),
                                Column('sid', String, nullable=True))
    NnmClubTopic0 = Table("nnmclub_topics", m0,
                          Column("id", Integer, ForeignKey('topics.id'), primary_key=True),
                          Column("hash", String, nullable=True))

    m1 = MetaData()
    NnmClubCredentials1 = Table("nnmclub_credentials", m1,
                                Column('username', String, primary_key=True),
                                Column('password', String, primary_key=True),
                                Column('user_id', String, nullable=True),
                                Column('sid', String, nullable=True),
                                Column('autologin_data', String, nullable=True))
    NnmClubTopic1 = Table("nnmclub_topics", m1,
                          Column("id", Integer, ForeignKey('topics.id'), primary_key=True),
                          Column("hash", String, nullable=True))

    versions = [
        (NnmClubCredentials0, NnmClubTopic0, UpgradeTestCase.copy(Topic.__table__, m0)),
        (NnmClubCredentials1, NnmClubTopic1, UpgradeTestCase.copy(Topic.__table__, m1)),
    ]

    def upgrade_func(self, engine, operation_factory):
        upgrade(engine, operation_factory)

    def _get_current_version(self):
        return get_current_version(self.engine)

    def test_empty_db_test(self):
        self._test_empty_db_test()

    def test_upgrade_empty_from_version_0(self):
        self._upgrade_from(None, 0)

    def test_upgrade_empty_from_version_1(self):
        self._upgrade_from(None, 1)

    def test_upgrade_filled_from_version_0(self):
        credential = {'username': 'monitorrent', 'password': 'p@$$w0rd',
                      'user_id': '9876543', 'sid': '0123456789abcdef0123456789abcdef'}

        self._upgrade_from([[credential]], 0)

        credentials = list(self.engine.execute(self.NnmClubCredentials1.select()))

        assert len(credentials) == 1
        assert credentials[0].username == 'monitorrent'
        assert credentials[0].user_id == '9876543'
        # the session already stored keeps working, the new column just starts out empty
        assert credentials[0].sid == '0123456789abcdef0123456789abcdef'
        assert credentials[0].autologin_data is None
