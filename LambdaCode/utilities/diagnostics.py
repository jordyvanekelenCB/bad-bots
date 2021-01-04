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

        LOGGER.info('================================ Bad bots results ================================')

        # pylint: disable=W1202
        LOGGER.info("Blocked source address: {0}.".format(source_ip))
        LOGGER.info("Blocked source address type: {0}.".format(source_ip_type))
