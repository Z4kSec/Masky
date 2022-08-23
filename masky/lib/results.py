import json
import logging
from .cert.misc import process_pfx

logger = logging.getLogger("masky")


class MaskyResults:
    def __init__(self):
        self.json_data = None
        self.errors = None
        self.hostname = None
        self.users = []

    def save_content_to_json(self, data):
        try:
            if data == b"\r\n":
                self.json_data = ""
            else:
                self.json_data = json.loads(data)
        except:
            self.json_data = None

    def parse_agent_errors(self, data):
        self.errors = str(data, "UTF-8")
        if "The parameter is incorrect".lower() in self.errors.lower():
            self.errors = ""
            logger.error(
                f"The provided CA name seems to be invalid, please check its value"
            )
        elif "The RPC server is unavailable".lower() in self.errors.lower():
            self.errors = ""
            logger.error(
                f"The provided CA server seems to be invalid or unreachable, please check its value"
            )
        elif (
            "Empty Certificate for the user".lower() in self.errors.lower()
            and not self.json_data
        ):
            self.errors = ""
            logger.error(
                f"Fail to retrieve a PEM from the provided template name, please check its value"
            )
        elif (
            data != b"\r\n"
            and not "Empty Certificate for the user".lower() in self.errors.lower()
        ):
            logger.debug(
                f"The Masky agent execution failed due to the following errors:\n{self.errors}"
            )

    def process_data(self):
        self.hostname = self.json_data[0].get("Hostname", None)
        for user_data in self.json_data:
            username = user_data.get("Username", None)
            cert = user_data.get("Cert", None)
            private_key = user_data.get("PrivateKey", None)
            if username and cert and private_key:
                user = User(username, cert, private_key)
                self.users.append(user)


class User:
    def __init__(self, username, cert, privatekey):
        self.domain, self.name = username.lower().split("\\")
        self.cert_from_pem = bytes(cert, "utf-8")
        self.pk_from_pem = bytes(privatekey, "utf-8")
        self.pfx, self.privatekey, self.cert = process_pfx(
            self.cert_from_pem, self.pk_from_pem
        )
        self.upn = f"{self.name}@{self.domain}".lower()
        self.nt_hash = ""
        self.ccache = ""
