import re
import logging
import socket
import ipaddress
from enum import IntEnum
from .toolbox import is_valid_file

logger = logging.getLogger("masky")


class TargetType(IntEnum):
    IP = 1
    HOST = 2
    CIDR = 3


class CIDR:
    def __init__(self, cidr):
        self.target = cidr

    def get(self):
        try:
            for ip in list(ipaddress.ip_network(self.target, False).hosts()):
                yield str(ip)
        except ValueError as e:
            logger.warn(f"Cannot parse the CIDR '{self.target}': {e}")
            return []


class Host:
    def __init__(self, host):
        self.target = host

    def get(self):
        """Get the IP linked to the hostname stored within this object"""
        try:
            socket.gethostbyname_ex(self.target)[-1]
            yield self.target.lower()
        except Exception as e:
            logger.warn(f"Can't resolve '{self.target}': {e}")
            return []


class IP:
    def __init__(self, ip):
        self._target = ip

    def get(self):
        try:
            yield self._target
        except socket.error:
            logger.warn(f"Cannot validate IP: '{self._target}'")
            return []


SCOPE_CLASS = {TargetType.CIDR: CIDR, TargetType.HOST: Host, TargetType.IP: IP}


class Targets:
    def __init__(self, targets):
        self.__raw_targets = targets
        self.scope = []

    def load(self):
        for target in self.__raw_targets:
            if is_valid_file(target):
                tmp_targets = []
                with open(target) as fd:
                    tmp_targets = fd.read().splitlines()
                for target in tmp_targets:
                    self.__add_to_scope(target)
            else:
                self.__add_to_scope(target)
        return self.scope

    def __add_to_scope(self, target):
        target_type = self.__check_target_type(target)
        items = SCOPE_CLASS[target_type](target)
        for target in items.get():
            if target not in self.scope:
                self.scope.append(target)

    def __check_target_type(self, target):
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}", target):
            return TargetType.CIDR
        elif re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", target):
            return TargetType.IP
        return TargetType.HOST
