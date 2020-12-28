""" Creates an AWS connection """

# pylint: disable=E0401
import boto3


class AWSConnection:
    """ This class is responsible for creating AWS connections """

    def __str__(self):
        return self.__class__.__name__

    @staticmethod
    def get_connection(aws_component) -> boto3.session:
        """ Returns a boto3 client given a specified AWS component """
        return boto3.client(aws_component)
