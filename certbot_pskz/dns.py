"""DNS Authenticator for Ps.kz DNS."""
import logging

# import json
import requests

import zope.interface

# from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Ps.kz DNS

    This Authenticator uses the Ps.kz DNS API to fullfill a dns-01 challenge.

    """

    description = "Obtain certificates using a DNS TXT record (if you are using Ps.kz for DNS)"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add) -> None:
        super(
            Authenticator,
            cls
        ).add_parser_arguments(
            add,
            default_propagation_seconds=120
        )
        add(
            "credentials",
            help="Path to Ps.kz credentials INI file",
            default="/etc/letsencrypt/pskz.ini"
        )

    def more_info(self) -> str:
        return "This plugin configures a DNS TXT record to respond to a dns-01 challenge using" +\
            "the Ps.kz API."

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            "credentials",
            "path to Ps.kz credentials INI file",
            {
                "email": "email of the Ps.kz account.",
                "password": "password of the Ps.kz account",
            }
        )

    def _perform(
        self,
        domain: str,
        validation_name: str,
        validation: str
    ) -> None:
        self._get_pskz_client().add_txt_record(validation_name, validation)

    def _cleanup(
        self,
        domain: str,
        validation_name: str,
        validation: str
    ) -> None:
        self._get_pskz_client().del_txt_record(validation_name, validation)

    def _get_pskz_client(self) -> "_PsKzClient":
        return _PsKzClient(
            self.credentials.conf("email"),
            self.credentials.conf("password")
        )


class _PsKzClient:
    """
    Encapsulates all communication with the Ps.kz
    """

    def __init__(self, email, password):
        self.http = requests.Session()
        self.options = {
            "email": email,
            "password": password,
            "io_encoding": "utf8",
            "show_input_params": 1,
            "output_format": "json",
            "input_format": "json",
        }

    def _authenticate(self):
        response = self.http.post()

    def add_txt_record(self, record_name, record_content):
        pass

    def del_txt_record(self, record_name, record_content):
        pass
