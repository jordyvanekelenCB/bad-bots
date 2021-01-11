""" Unit test for ALB Log parser class """

import os
import sys
import inspect
import time
# pylint: disable=E0401
import pytest

# Fix module import form parent directory error.
# Reference: https://stackoverflow.com/questions/55933630/
# python-import-statement-modulenotfounderror-when-running-tests-and-referencing
CURRENT_DIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
PROJECT_ROOT_SRC = "%s/LambdaCode" % os.path.dirname(PROJECT_ROOT)

# Set up sys path
sys.path.insert(0, PROJECT_ROOT_SRC)

# Import project classes
# pylint: disable=C0413
# pylint: disable=W0621
from LambdaCode import app
from LambdaCode.bad_bots import BadBots
from LambdaCode.connection.aws_wafv2_connection import AWSWAFv2Connection


@pytest.fixture
def get_mock_config():
    """ Return the mocked config parser with arbitrary values of the components to be tested """

    # Create Bad Bots mock config section
    mock_config_section_aws = {
        'IP_SET_BAD_BOTS_SCOPE': 'REGIONAL',
        'IP_SET_BAD_BOTS_IPV4_NAME': 'ip_set_bad_bots_ipv4_test',
        'IP_SET_BAD_BOTS_IPV6_NAME': 'ip_set_bad_bots_ipv6_test'
    }

    mock_config_section_geolocation = {
        'API_URL': 'https://extreme-ip-lookup.com/json/'
    }

    # Mock config section
    mock_config = {
        'AWS_WAF': mock_config_section_aws,
        'GEOLOCATION': mock_config_section_geolocation
    }

    return mock_config

@pytest.fixture()
def get_mock_event_ipv4():
    """ Fixture for retrieving mock event """

    event = {
        "httpMethod": "GET",
        "body": "<script></script>EXEC",
        "path": "/users",
        "queryStringParameters": {},
        "pathParameters": {
            "proxy": "users"
        },
        "requestContext": {
            "accountId": "333333333",
            "identity": {
                "sourceIp": "1.1.1.1",
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6)"
                             " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36",
            },
            "resourcePath": "/{proxy+}",
            "httpMethod": "GET",
        },
        "headers" : {
            "User-Agent": "Mozilla/5.0 (compatible; Sosospider/2.0; +http://help.soso.com/webspider.htm)"
        }
    }

    return event


@pytest.fixture(autouse=True)
def cleanup_wafv2(get_mock_config):
    """ Cleans up WAFv2 IP sets before each system test """

    # Update IPv4 IP set with empty list
    AWSWAFv2Connection(get_mock_config, BadBots.SourceIPType.IPV4).update_ip_set([])

    # Update IPv6 IP set with empty list
    AWSWAFv2Connection(get_mock_config, BadBots.SourceIPType.IPV6).update_ip_set([])


# pylint: disable=R0914
def test_system_ipv4(get_mock_config, get_mock_event_ipv4):
    """ Run system test to make sure all AWS components are working together accordingly. """

    # !ARRANGE!
    app.CONFIG = get_mock_config

    # !ACT!

    start_time = time.time()  # Record starting time
    app.lambda_handler(get_mock_event_ipv4, None)  # Execute entry point

    # !ASSERT!

    # Check if IP set contains plausible entries
    wafv2_ip_set_ipv4_bad_bots_blocked_test_response = AWSWAFv2Connection \
        (get_mock_config, BadBots.SourceIPType.IPV4).retrieve_ip_set()

    # Get ip addresses from response
    ip_set_bad_bots_ipv4_test = wafv2_ip_set_ipv4_bad_bots_blocked_test_response["IPSet"]["Addresses"]

    # Assert IP sets contain 1 IPv4 address
    assert len(ip_set_bad_bots_ipv4_test) == 1

    # Assert IP address is as expected
    assert ip_set_bad_bots_ipv4_test[0] == '1.1.1.1/32'

    # Assert system test was completed within allotted timeframe (test performance)
    total_duration_in_ms = ((time.time() - start_time) * 1000)
    assert total_duration_in_ms < 10000
