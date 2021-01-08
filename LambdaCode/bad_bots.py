""" This file contains the BadBots class """

# pylint: disable=E0611
import logging
from enum import Enum
from ipaddress import ip_address
from ipaddress import IPv4Network
from ipaddress import IPv6Network
from connection import AWSWAFv2Connection


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

        # Get source IP type
        source_ip_type = self.get_ip_type_by_address(source_ip)

        # Check the source IP type and then update the respective IP set
        if source_ip_type == self.SourceIPType.IPV4:
            source_ip_address_list.append(IPv4Network(source_ip).with_prefixlen)
            self.update_bad_bots_ip_set(self.SourceIPType.IPV4, source_ip_address_list)
        if source_ip_type == self.SourceIPType.IPV6:
            source_ip_address_list.append(IPv6Network(source_ip).with_prefixlen)
            self.update_bad_bots_ip_set(self.SourceIPType.IPV6, source_ip_address_list)

        bad_bots_output = {
            "source_ip": source_ip,
            "source_ip_type": source_ip_type.value
        }

        return bad_bots_output

    def get_ip_type_by_address(self, source_ip):
        """ Get the IP address type based on the IP address provided  """

        # Identify IP version
        source_ip_type = "IPV%s" % ip_address(source_ip).version

        if source_ip_type == "IPV4":
            return self.SourceIPType.IPV4

        return self.SourceIPType.IPV6

    def update_bad_bots_ip_set(self, source_ip_type, source_ip_address_list):
        """ Updates a bad bots IP set, depending on the IP address type """

        aws_wafv2_connection = None

        if source_ip_type == self.SourceIPType.IPV4:
            aws_wafv2_connection = AWSWAFv2Connection(self.config, self.SourceIPType.IPV4)
        elif source_ip_type == self.SourceIPType.IPV6:
            aws_wafv2_connection = AWSWAFv2Connection(self.config, self.SourceIPType.IPV6)

        # Get current IP set
        wafv2_response = aws_wafv2_connection.retrieve_ip_set()
        current_block_list_entries = wafv2_response["IPSet"]["Addresses"]

        # Merge block lists
        merged_block_list_entries = source_ip_address_list + current_block_list_entries

        # Update IP set with with newly merged block list
        aws_wafv2_connection.update_ip_set(merged_block_list_entries)

    class SourceIPType(Enum):
        """ Subclass enum for BadBots class """
        IPV4 = 'IPV4'
        IPV6 = 'IPV6'
