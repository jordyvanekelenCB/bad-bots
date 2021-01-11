""" This file contains the HTTPGet class """

# pylint: disable=E0401
import logging
import urllib3

# Setup logger
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


class HTTPGet:
    """ This class is responsible for making requests to the IP list parser provider URL's and returning the result """

    def __str__(self):
        return self.__class__.__name__

    @staticmethod
    def http_get_contents(url) -> str:
        """ Gets the content of an URL and returns it """

        # Clean url
        url = str(url).strip('\\')
        url = str(url).strip('\n')

        try:
            # Fixed SSL bug on MacOS: /Applications/Python\ 3.8/Install\ Certificates.command
            http = urllib3.PoolManager()
            http_response = http.request('GET', url, timeout=5)
            http_response_content = http_response.data

            if http_response.status == 200:
                return http_response_content.decode('utf-8')

            return ''

        # pylint: disable=W0703
        except Exception as error:
            # pylint: disable=W1202
            LOGGER.error('Error. Could not connect to: {0}. Error message: {1}'.format(url, error))

        return ''
