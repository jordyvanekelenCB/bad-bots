""" This file contains the BadBots class """

import logging
from enum import Enum
from ipaddress import ip_address
from ipaddress import IPv4Network
from ipaddress import IPv6Network
from .connection import AWSWAFv2Connection


# Setup logger
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


class BadBots:
    """ This class is responsible for the Bad bots component logic. It collects the source IP address of the target
        that made a request to the honeypot trap endpoint and blocks it. """

    config_section_bad_bots = 'BAD_BOTS'

    def __init__(self, config, event):
        self.config = config
        self.event = event

    def parse_bad_bots(self):
        """ Entry point """

        source_ip_address_list = []

        # Get source IP address
        source_ip = str(self.event['requestContext']['identity']['sourceIp'])

        source_ip_type = "IPV%s" % ip_address(source_ip).version

        # Check the source IP type and then update the respective IP set
        if source_ip_type == "IPV4":
            source_ip_address_list.append(IPv4Network(source_ip).with_prefixlen)
            self.update_bad_bots_ip_set(self.SourceIPType.IPV4, source_ip_address_list)
        elif source_ip_type == "IPV6":
            source_ip_address_list.append(IPv6Network(source_ip).with_prefixlen)
            self.update_bad_bots_ip_set(self.SourceIPType.IPV6, source_ip_address_list)

        bad_bots_output = {
            "source_ip": source_ip,
            "source_ip_type": source_ip_type
        }

        return bad_bots_output

    def update_bad_bots_ip_set(self, source_ip_type, source_ip_address_list):
        """ Updates a bad bots ip set, depending on the IP address type (IPv4/IPv6) """

        aws_wafv2_connection = None

        if source_ip_type.value == "IPV4":
            aws_wafv2_connection = AWSWAFv2Connection(self.config, self.SourceIPType.IPV4)
        elif source_ip_type.value == "IPV6":
            aws_wafv2_connection = AWSWAFv2Connection(self.config, self.SourceIPType.IPV6)

        aws_wafv2_connection.update_ip_set(source_ip_address_list)

    class SourceIPType(Enum):
        """ Subclass enum for BadBots class """
        IPV4 = 'IPV4'
        IPV6 = 'IPV6'
