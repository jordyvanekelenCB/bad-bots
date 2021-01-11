""" This module holds the Diagnostics class """

import logging

# Setup logger
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


class Diagnostics:
    """ This class is responsible for printing diagnostic results """

    def __str__(self):
        return self.__class__.__name__

    @staticmethod
    def print_results(bad_bots_output) -> None:
        """ Prints bad bots results to screen """

        bad_bots_results = bad_bots_output['bad_bots_results']

        source_ip = bad_bots_results['source_ip']
        source_ip_type = bad_bots_results['source_ip_type']
        is_bot = bad_bots_results['is_bot']
        bot_confidence_score = bad_bots_results["bot_confidence_score"]

        LOGGER.info('================================ Bad bots results ================================')

        # pylint: disable=W1202
        LOGGER.info("Client address: {0}.".format(source_ip))
        LOGGER.info("Client address type: {0}.".format(source_ip_type))

        if is_bot:
            LOGGER.info("Client {0} is bot: TRUE.".format(source_ip))
        else:
            LOGGER.info("Client {0} is bot: FALSE.".format(source_ip))

        LOGGER.info("Bot confidence score: {0}.".format(bot_confidence_score))
