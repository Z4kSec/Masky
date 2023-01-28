import argparse
import logging
import sys
from getpass import getpass
from ..utils.targets import Targets
from ..utils.logger import load_custom_logger

logger = logging.getLogger("masky")


class Options:
    def __init__(self, cli_parser):
        self.ca = cli_parser.certificate_authority
        self.template = cli_parser.template
        self.dc_ip = cli_parser.dc_ip
        self.domain = cli_parser.domain
        self.user = cli_parser.user
        self.password = cli_parser.password
        self.hashes = cli_parser.hashes
        self.kerberos = cli_parser.kerberos
        self.no_hash = cli_parser.no_hash
        self.no_pfx = cli_parser.no_pfx
        self.no_ccache = cli_parser.no_ccache
        self.targets = cli_parser.targets
        self.threads = cli_parser.threads
        self.verbose = cli_parser.verbose
        self.timestamps = cli_parser.timestamps
        self.output = cli_parser.output
        self.stealth = cli_parser.stealth
        self.exe_path = cli_parser.exe
        self.file_args = cli_parser.file_args

    def process(self):
        logger.info("Loading options...")
        if not self.check_secret() or not self.check_targets() or not self.check_misc():
            return False
        return True

    def check_targets(self):
        targets = Targets(self.targets)
        self.targets = targets.load()
        if not self.targets:
            logger.error("No valid targets submitted")
            return False
        logger.info(f"{len(self.targets)} target(s) loaded")
        return True

    def check_secret(self):
        if self.password:
            return True
        elif self.hashes and ":" in self.hashes:
            return True
        elif self.kerberos:
            self.user = ""
            self.password = ""
            self.hashes = None
            return True
        elif not self.password and not self.hashes and not self.kerberos:
            self.password = getpass()
            return True

        logger.error("Invalid credentials submitted")
        return False

    def check_misc(self):
        if self.threads not in range(1, 15):
            logger.warn(
                "The threadpool size cannot exceed 15, enforcing to the maximum value"
            )
            self.threads = 15
        if self.timestamps:
            load_custom_logger(ts=True)
        if self.verbose:
            logger.setLevel(logging.DEBUG)
        return True


def get_cli_args():
    parser = argparse.ArgumentParser(prog="Masky")

    # Masky attributes
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable debugging messages",
    )
    parser.add_argument(
        "-ts",
        "--timestamps",
        action="store_true",
        default=False,
        help="Display timestamps for each log",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        action="store",
        default=1,
        help="Threadpool size (max 15)",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        type=str,
        action="store",
        help="Targets in CIDR, hostname and IP formats are accepted, from a file or not",
    )

    # Authentication attributes
    group_auth = parser.add_argument_group("Authentication")
    group_auth.add_argument(
        "-d",
        "--domain",
        action="store",
        default=".",
        help="Domain name to authenticate to",
    )
    group_auth.add_argument(
        "-u",
        "--user",
        action="store",
        help="Username to authenticate with",
    )
    group_auth.add_argument(
        "-p",
        "--password",
        default=None,
        action="store",
        help="Password to authenticate with",
    )
    group_auth.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        default=False,
        help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on "
        "target parameters.",
    ),
    group_auth.add_argument(
        "-H",
        "--hashes",
        action="store",
        default=None,
        help="Hashes to authenticate with (LM:NT, :NT or :LM)",
    )

    # Connection attributes
    group_connect = parser.add_argument_group("Connection")
    group_connect.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        default=None,
        help="IP Address of the domain controller. If omitted it will use "
        "the domain part (FQDN) specified in the target parameter",
    )
    group_connect.add_argument(
        "-ca",
        "--certificate-authority",
        action="store",
        help="Certificate Authority Name (SERVER\CA_NAME)",
        required=True,
    )
    group_connect.add_argument(
        "-T",
        "--template",
        action="store",
        default="User",
        help="Template name allowing users to authenticate with (default: User)",
    )

    # Custom agent
    group_custom_agent = parser.add_argument_group("Custom agent")
    group_custom_agent.add_argument(
        "-e",
        "--exe",
        action="store",
        default=None,
        help="Path to a custom executable masky agent to be deployed",
    )
    group_custom_agent.add_argument(
        "-fa",
        "--file-args",
        action="store_true",
        default=False,
        help="If enabled, the Masky agent will load arguments from an "
        " automatically generated file (useful when packed or using a loader)",
    )
    group_custom_agent.add_argument(
        "-s",
        "--stealth",
        action="store_true",
        default=False,
        help="If set, the agent will be executed by modifying an existing "
        " service (RasAuto) rather than created a random one",
    )
    # Results attributes
    group_results = parser.add_argument_group("Results")
    group_results.add_argument(
        "-nh",
        "--no-hash",
        action="store_true",
        default=False,
        help="Do not request NT hashes",
    )
    group_results.add_argument(
        "-nt",
        "--no-ccache",
        action="store_true",
        default=False,
        help="Do not save ccache files",
    )
    group_results.add_argument(
        "-np",
        "--no-pfx",
        action="store_true",
        default=False,
        help="Do not save pfx files",
    )
    group_results.add_argument(
        "-o",
        "--output",
        default="masky-output",
        help="Local path to a folder where Masky results will be stored"
        " (automatically creates the folder if it does not exit)",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()
