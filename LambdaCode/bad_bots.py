""" This file contains the BadBots class """

# pylint: disable=E0611
# pylint: disable=E0401
import logging
import json
import re
from enum import Enum
from ipaddress import ip_address
from ipaddress import IPv4Network
from ipaddress import IPv6Network
from models import Bot
from connection import AWSWAFv2Connection
from connection import HTTPGet
from crawlerdetect import CrawlerDetect


# Setup logger
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


class BadBots:
    """ This class is responsible for the Bad bots component logic. It collects the source IP address of the target
        that made a request to the honeypot trap endpoint and blocks it. """

    config_section_bad_bots = 'BAD_BOTS'
    config_section_geolocation = 'GEOLOCATION'

    def __init__(self, config, event):
        self.config = config
        self.event = event

    def parse_bad_bots(self):
        """ Entry point """

        # The threshold confidence of the bot. If the bot confidence score is equal or higher than the threshold,
        # block the bot.
        bot_confidence_threshold = 7

        # Setup properties
        bot = Bot()
        bot.source_ip = str(self.event['requestContext']['identity']['sourceIp'])
        bot.source_ip_type = self.get_ip_type_by_address(bot.source_ip)
        bot.http_user_agent = str(self.event['headers']['User-Agent'])
        bot.http_method = str(self.event['httpMethod'])
        bot.http_body = str(self.event['body'])
        bot.http_query_string_parameters = str(self.event['queryStringParameters'])

        if bot.source_ip_type == self.SourceIPType.IPV4:
            bot.geolocation = self.get_geolocation(bot.source_ip)
        else:
            bot.geolocation = None

        # Do confidence check based on bot properties
        bot_confidence_score = self.check_bot_confidence(bot)

        # Was detected as bot? For diagnostics
        is_bot = False

        if bot_confidence_score >= bot_confidence_threshold:

            is_bot = True

            # Check the source IP type and then update the respective IP set
            if bot.source_ip_type == self.SourceIPType.IPV4:
                self.update_bad_bots_ip_set(self.SourceIPType.IPV4, [IPv4Network(bot.source_ip).with_prefixlen])
            if bot.source_ip_type == self.SourceIPType.IPV6:
                self.update_bad_bots_ip_set(self.SourceIPType.IPV6, [IPv6Network(bot.source_ip).with_prefixlen])

        bad_bots_output = {
            "source_ip": bot.source_ip,
            "source_ip_type": bot.source_ip_type.value,
            "is_bot": is_bot,
            "bot_confidence_score": bot_confidence_score
        }

        return bad_bots_output

    def get_geolocation(self, source_ip):
        """ Gets the country of origin based on the IP address """

        country = None

        try:
            response = HTTPGet.http_get_contents(self.config[self.config_section_geolocation]["API_URL"] + source_ip)
            json_data = json.loads(response)
            country = json_data["country"]

        except Exception as error:
            LOGGER.error(error)
            raise

        return country

    # pylint: disable=R0201
    def check_bot_confidence(self, bot):
        """ Indicates whether the client making the request is a bot or not by analysing the request and
            returning a confidence score
        """

        bot_confidence_score = 0

        # Confidence: Check user agent

        # Check if user agent is null
        if bot.http_user_agent == '':
            bot_confidence_score += 3

        # Use crawler detection
        crawler_detect = CrawlerDetect()
        is_crawler = crawler_detect.isCrawler(bot.http_user_agent)

        if is_crawler:
            bot_confidence_score += 7

        # Confidence: Check user agent, based on
        # https://www.sans.org/reading-room/whitepapers/detection/identify-malicious-http-requests-34067
        if bot.http_method in ["CONNECT", "PUT", "DELETE"]:
            bot_confidence_score += 5

        # Confidence: Check geolocation
        if bot.geolocation is None:
            pass # IPv6 geolocation has not been implemented yet
        else:
            # If the geolocation is not a country we ship / sell to increase bot confidence
            if bot.geolocation not in ["Netherlands", "Belgium", "Germany"]:
                bot_confidence_score += 5

        #Confidence check: body / query string parameters

        # Check for SQL injections

        sqli_regex = re.compile\
            (r'\b(ALTER|CREATE|DELETE|DROP|EXEC(UTE){0,1}|INSERT( +INTO){0,1}|MERGE|SELECT|UPDATE|UNION( +ALL){0,1})\b')

        if sqli_regex.search(bot.http_body) or sqli_regex.search(bot.http_query_string_parameters):
            bot_confidence_score += 8

        # Check for XSS
        xss_regex_1 = re.compile(r'((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)')
        if xss_regex_1.search(bot.http_body) or sqli_regex.search(bot.http_query_string_parameters):
            bot_confidence_score += 8

        xss_regex_2 = re.compile(r'/((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)/I')
        if xss_regex_2.search(bot.http_body) or sqli_regex.search(bot.http_query_string_parameters):
            bot_confidence_score += 8

        return bot_confidence_score

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
