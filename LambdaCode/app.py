""" Entry point file """

# pylint: disable=E0401
import os
import configparser
import logging
from bad_bots import BadBots
from utilities import Diagnostics

# Setup logger
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

# Setup config parser
CONFIG = configparser.ConfigParser()
CONFIG.read(os.path.join(os.path.dirname(__file__), 'config', 'config.ini'))

# pylint: disable=W0613
def lambda_handler(event, context):
    """ Entry point of the application """

    bad_bots_output = None

    try:
        # Activate Bad Bots module
        bad_bots_output = BadBots(CONFIG, event).parse_bad_bots()

    except Exception as error:
        LOGGER.error(error)
        raise

    finally:
        # The HTTP response returned to the bot
        message = "message: [{0}] Thanks for the visit.".format(bad_bots_output['source_ip'])
        response = {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': message
        }

        # Send results to diagnostics to print results
        Diagnostics.print_results({'bad_bots_results': bad_bots_output, 'config': CONFIG})

    # Return response to bad bot
    return response
