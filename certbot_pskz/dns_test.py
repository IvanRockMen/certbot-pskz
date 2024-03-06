import os
# import unittest

# import json
import mock
import requests

# from certbot import errors

from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

EMAIL = "foo"
PASSWORD = "bar"

HTTP_ERROR = requests.exceptions.RequestException


class AuthenticatorTest(
    test_util.TempDirTestCase,
    dns_test_common.BaseAuthenticatorTest
):

    def setUp(self):
        from certbot_pskz.dns import Authenticator

        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write({
            "pskz_email": EMAIL,
            "pskz_password": PASSWORD,
        }, path)

        self.config = mock.MagicMock(
            pskz_credentials=path,
            pskz_propagation_seconds=0
        )

        self.auth = Authenticator(self.config, "pskz")

        self.mock_client = mock.MagicMock()
        # _get_pskz_client | pylint: disable=protected-access
        self.auth._get_pskz_client = mock.MagicMock(
            return_value=self.mock_client
        )

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [
            mock.call.add_txt_record(
                "_acme-challenge." + DOMAIN,
                mock.ANY
            )
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [
            mock.call.del_txt_record(
                "_acme-challenge." + DOMAIN,
                mock.ANY
            )
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)
