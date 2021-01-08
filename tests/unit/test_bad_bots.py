""" Unit test containing tests for IP list parser class """

import sys
import os
import inspect
import configparser
# pylint: disable=E0401
import pytest

# Fix module import form parent directory error.
# Reference: https://stackoverflow.com/questions/55933630/
# python-import-statement-modulenotfounderror-when-running-tests-and-referencing
CURRENT_DIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
PROJECT_ROOT_SRC = "%s/LambdaCode" % os.path.dirname(PROJECT_ROOT)

# Set up configuration path
CONFIG_PATH = os.path.join(os.path.dirname(PROJECT_ROOT_SRC + "/LambdaCode"), 'config', 'config.ini')

# Set up sys path
sys.path.insert(0, PROJECT_ROOT_SRC)

# Import project classes
# pylint: disable=C0413
from bad_bots import BadBots

@pytest.fixture()
def setup_config():
    """ Fixture for setting up configuration parser """

    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)

    return config

@pytest.fixture()
def get_mock_event():
    """ Fixture for retrieving mock event """

    event = {
        "httpMethod": "GET",
        "//body": "{\"name\": \"Sam\"}",
        "resource": "/{proxy+}",
        "queryStringParameters": {},
        "pathParameters": {
            "proxy": "users"
        },
        "requestContext": {
            "accountId": "222222222",
            "identity": {
                "sourceIp": "2a02:a445:6d36:1:1e3:a188:313c:1d31",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_1_6) "
                             "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2743.116 Safari/537.36",
            },
            "resourcePath": "/{proxy+}",
            "httpMethod": "GET",
            "apiId": "xxxxxxxxxx"
        }
    }

    return event


# pylint: disable=W0621
# pylint: disable=R0914
def test_get_ip_type_by_address(setup_config, get_mock_event):
    """ Unit test get_ip_type_by_address method of the Bad Bots class """

    # !ARRANGE!
    bad_bots = BadBots(setup_config, get_mock_event)

    ipv4_address_1 = '1.1.1.1'
    ipv4_address_2 = '11.22.33.44'
    ipv4_address_3 = '123.123.123.123'

    ipv6_address_1 = '2a02:a445:6d36:1:1e3:a188:313c:1d31'
    ipv6_address_2 = '3731:54:65fe:2::a7'
    ipv6_address_3 = 'fd07:a47c:3742:823e:3b02:76:982b:463'

    # !ACT!

    # Detect the IP type of provided IP addresses
    ipv4_address_1_type = bad_bots.get_ip_type_by_address(ipv4_address_1)
    ipv4_address_2_type = bad_bots.get_ip_type_by_address(ipv4_address_2)
    ipv4_address_3_type = bad_bots.get_ip_type_by_address(ipv4_address_3)

    ipv6_address_1_type = bad_bots.get_ip_type_by_address(ipv6_address_1)
    ipv6_address_2_type = bad_bots.get_ip_type_by_address(ipv6_address_2)
    ipv6_address_3_type = bad_bots.get_ip_type_by_address(ipv6_address_3)

    # !ASSERT!

    # Assert IP addresses are of type IPv4
    assert ipv4_address_1_type.value == BadBots.SourceIPType.IPV4.value
    assert ipv4_address_2_type.value == BadBots.SourceIPType.IPV4.value
    assert ipv4_address_3_type.value == BadBots.SourceIPType.IPV4.value

    # Assert IP addresses are of type IPv6
    assert ipv6_address_1_type.value == BadBots.SourceIPType.IPV6.value
    assert ipv6_address_2_type.value == BadBots.SourceIPType.IPV6.value
    assert ipv6_address_3_type.value == BadBots.SourceIPType.IPV6.value
