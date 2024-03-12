"""DNS Authenticator for Ps.kz DNS."""
import logging

import uuid
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

    description = "Obtain certificates using a DNS" +\
        "TXT record (if you are using Ps.kz for DNS)"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(
        cls,
        add,
        default_propagation_seconds=120
    ) -> None:
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
        return "This plugin configures a DNS TXT" +\
            " record to respond to a dns-01 challenge using" +\
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
        self._get_pskz_client(domain).add_txt_record(
            validation_name,
            validation
        )

    def _cleanup(
        self,
        domain: str,
        validation_name: str,
        validation: str
    ) -> None:
        self._get_pskz_client(domain).del_txt_record(
            validation_name,
            validation
        )

    def _get_pskz_client(self, domain) -> "_PsKzClient":
        client = _PsKzClient(
            self.credentials.conf("email"),
            self.credentials.conf("password")
        )
        client.setup_domain(domain)
        return client


class _PsKzClient:
    """
    Encapsulates all communication with the Ps.kz
    """
    _AUTH_URL = "https://auth.ps.kz/graphql?lang=ru&opname=LoginMutation"
    _MUTATION_RECORD_URL = "https://console.ps.kz/dns/graphql"
    _CHALLENGE_URL = "https://auth.ps.kz/oidc/login"

    def __init__(self, email, password):
        self.http = requests.Session()
        self.domain = ""
        self.options = {
            "email": email,
            "password": password,
            "io_encoding": "utf8",
            "show_input_params": 1,
            "output_format": "json",
            "input_format": "json",
        }

    def setup_domain(self, domain):
        self.domain = domain

    def _authenticate(self):
        data = {
            "operationName": "LoginMutation",
            "variables": {
                "email": self.options.get("email", ""),
                "password": self.options.get("password", ""),
                "remember": True,
            },
            "query": """
                mutation LoginMutation(
                    $email: String!,
                    $token: String,
                    $password: String!,
                    $remember: Boolean
                ) {
                    auth {
                        guestLogin(
                            email: $email
                            token: $token
                            password: $password
                            remember: $remember
                        ) {
                            totp
                            emailVerified
                            user {
                                phoneVerified
                                __typename
                            }
                            error {
                                name
                                message
                                ... on UserDeactivatedError {
                                    deactivationReason
                                    __typename
                                }
                                __typename
                            }
                            __typename
                        }
                        __typename
                    }
                    __typename
                }

            """  # noqa: E501
        }
        response = self.http.post(self._AUTH_URL, json=data)
        resp_data = response.json()
        error_data = resp_data['data']['auth']['guestLogin'].get("error")
        if error_data:
            error_name = error_data['name']
            error_message = error_data['message']
            raise requests.exceptions.HTTPError(f"{error_name}: {error_message}")  # noqa: E501
        login_challenge_params = {"login_challenge": f"{uuid.uuid4().hex}"}
        resp = self.http.get(
            self._CHALLENGE_URL,
            params=login_challenge_params
        )
        if resp != 200:
            raise requests.exceptions.HTTPError(
                f"Login challenge was ended with error: {resp.status_code}. Reason: {resp.text}"  # noqa: E501
            )

    def add_txt_record(self, record_name, record_content):
        graphql_query = """
            mutation CreateDNSRecord(
                $zoneName: string!,
                $recordData: RecordCreateInput!
            ) {
                dns {
                    record {
                        create(
                            zoneName: $zoneName,
                            createData: $recordData
                        ) {
                            name
                            records {
                                name
                                type
                                value
                                ttl
                            }
                        }
                    }
                }
            }
        """  # noqa: E501

        variables = {
            "zoneName": self.domain,
            "recordData": {
                "name": record_name,
                "type": "TXT",
                "value": record_content,
                "ttl": 600,
            }
        }

        self._authenticate()

        response = self.http.post(
            self._MUTATION_RECORD_URL,
            json={"query": graphql_query, "variables": variables},
        )
        if response.status_code != 200:
            raise Exception(
                "Failed to add records in ps.kz." +
                f" Status code: {response.status_code}," +
                f" Reason: {response.text}"
            )

        resp_data = response.json()
        error_data = resp_data.get("error")

        if error_data:
            error = error_data["errors"][0]["message"]
            raise requests.exceptions.HTTPError(f"Error: {error}")

    def del_txt_record(self, record_name, record_content):

        get_dns_query = """
            query Query($domainName) {
                dns {
                    zone(name: $domainName) {
                        id
                        name
                        records {
                            id
                            name
                            type
                            value
                            ttl
                        }
                    }
                }
            }
        """

        self._authenticate()
        variables = {
            "domainName": self.domain
        }

        response = self.http.post(
            self._MUTATION_RECORD_URL,
            json={"query": get_dns_query, "variables": variables}
        )

        if response.status_code != 200:
            raise Exception(f"Error for get_dns_records with status: {response.status_code}. Reason: f{response.text}")  # noqa: E501

        result = response.json()
        error_data = result.get("error")
        if error_data:
            error = error_data["errors"][0]["message"]
            raise requests.exceptions.HTTPError(f"Error: {error}")

        records = result["data"]["dns"]["zone"]["records"]

        record_id = ""
        for record in records:
            if record["type"] == "TXT" and record["value"] == record_content:
                record_id = record["id"]
        graphql_query = """
            mutation DeleteDnsRecord($zoneName: string!, $recordId: string!) {
                dns {
                    record {
                        delete(
                            zoneName: $zoneName,
                            recordId: $recordId
                        ) {

                        }
                    }
                }
            }
        """

        variables = {
            "zoneName": self.domain,
            "recordId": record_id,
        }

        response = self.http.post(
            self._MUTATION_RECORD_URL,
            json={"query": graphql_query, "variables": variables},
        )

        if response.status_code != 200:
            raise Exception(f"Error deleting record. Status {response.status_code}. Reason: {response.text}")  # noqa: E501

        result = response.json()

        error_data = result.get("error")
        if error_data:
            error = error_data["errors"][0]["message"]
            raise requests.exceptions.HTTPError(f"Error: {error}")
