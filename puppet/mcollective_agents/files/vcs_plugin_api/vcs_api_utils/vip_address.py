##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# python *netaddr* package is not present on.
# This is just an utility class to deal with
# IPs tools. By no means it pretends to
# substitute netaddr IPNetwork, IPAddress,...
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

import socket


class VIPAddressException(Exception):
    pass


class VIPAddressInvalidAddressException(VIPAddressException):
    pass


class VIPAddressInvalidPrefixLenException(VIPAddressException):
    pass


class VIPAddress(object):
    def __init__(self, ipaddress):
        validator = lambda family: VIPAddress.is_ip_family(family, ipaddress)
        prefixlen = VIPAddress.get_prefixlen(ipaddress)

        if not any([validator(socket.AF_INET),
                     validator(socket.AF_INET6)]):
            raise VIPAddressInvalidAddressException(ipaddress)
        elif ((prefixlen is not None) and
              ((validator(socket.AF_INET) and not (0 <= prefixlen <= 32)) or
               (validator(socket.AF_INET6) and not (0 <= prefixlen <= 128)))):
            raise VIPAddressInvalidPrefixLenException(ipaddress)

        self.ipaddress = ipaddress

    def __repr__(self):
        return "{0}('{1}')".format(
                    self.__class__.__name__, str(self.ipaddress))

    def __str__(self):
        return str(self.ipaddress)

    @staticmethod
    def is_ip_family(family, ipaddress):
        try:
            address = VIPAddress.get_address(ipaddress)
            socket.inet_pton(family, address)
            return True
        except socket.error:
            return False

    @staticmethod
    def get_address(ipaddress):
        return str(ipaddress.split("/", 1)[0])

    @staticmethod
    def get_prefixlen(ipaddress):
        prefixlen = ipaddress.split("/", 1)[1] if "/" in ipaddress else None
        if prefixlen and not prefixlen.isdigit():
            raise VIPAddressInvalidPrefixLenException(ipaddress)
        return int(prefixlen) if prefixlen else None

    def is_ipv4(self):
        return self.is_ip_family(socket.AF_INET, self.ipaddress)

    def is_ipv6(self):
        return not self.is_ipv4()

    @property
    def version(self):
        return 4 if self.is_ipv4() else 6

    @property
    def ip(self):
        return self.get_address(self.ipaddress)

    @property
    def prefixlen(self):
        return self.get_prefixlen(self.ipaddress)

    @property
    def netmask(self):
        """
        https://stackoverflow.com/questions/33750233/convert-cidr-to-subnet-mask-in-python
        """
        if self.prefixlen:
            host_bits = 32 - int(self.prefixlen)
            pack = struct.pack('!I', (1 << 32) - (1 << host_bits))
            netmask = socket.inet_ntoa(pack)
        else:
            netmask = None
        return netmask
