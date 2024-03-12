"""
Authenticator tests
"""

import os
import unittest

import mock

from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

from certbot_pskz.dns import Authenticator

EMAIL = "foo"
PASSWORD = "bar"

patch_display_util = test_util.patch_display_util


class AuthenticatorTest(
    test_util.TempDirTestCase,
    dns_test_common.BaseAuthenticatorTest
):

    """
    Test for Authenticator class
    """
    def setUp(self):
        """
        Setup for testcase with test Authenticator
        """
        super().setUp()

        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write({
            "pskz_email": EMAIL,
            "pskz_password": PASSWORD,
        }, path)

        super().setUp()
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

    @patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        """
        Test perform function
        """
        self.auth.perform([self.achall])

        self.mock_client.add_txt_record.assert_called_with(
            "_acme-challenge." + DOMAIN, mock.ANY
        )

    @patch_display_util()
    def test_cleanup(self, unused_mock_get_utility):
        """
        Test delete usecase
        """
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth.perform([self.achall])
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        self.mock_client.del_txt_record.assert_called_with(
            "_acme-challenge." + DOMAIN, mock.ANY
        )


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
