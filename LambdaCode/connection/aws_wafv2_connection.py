""" AWS WAF v2 connection """

# pylint: disable=E0611
# pylint: disable=E0401
from connection.aws_connection import AWSConnection


class AWSWAFv2Connection:
    """ This class is responsible for handling connections to AWS WAF v2 """

    config_section_waf = 'AWS_WAF'

    def __init__(self, config, ip_set_bad_bots_list_type):
        self.boto_wafv2_client = AWSConnection().get_connection('wafv2')

        # Retrieve config parser
        self.config = config

        # Setup instance attributes
        if ip_set_bad_bots_list_type.value == 'IPV4':
            self.ip_set_blocked_name = self.config[self.config_section_waf]['IP_SET_BAD_BOTS_IPV4_NAME']

        elif ip_set_bad_bots_list_type.value == 'IPV6':
            self.ip_set_blocked_name = self.config[self.config_section_waf]['IP_SET_BAD_BOTS_IPV6_NAME']

        self.ip_set_blocked_scope = self.config[self.config_section_waf]['IP_SET_BAD_BOTS_SCOPE']
        self.ip_set_blocked_identifier = self.retrieve_ip_set_identifier()

    def retrieve_ip_set_identifier(self) -> str:
        """ Get ip set identifier by calling wafv2.list_ip_sets because the resource ID has to be fetched manually after
            creating the stack resource of the ip set.
         """

        ip_set_list = self.boto_wafv2_client.list_ip_sets(Scope=self.ip_set_blocked_scope)

        ip_set_identifier = ''

        for ip_set in ip_set_list["IPSets"]:
            if ip_set["Name"] == self.ip_set_blocked_name:
                ip_set_identifier = ip_set["Id"]

        return ip_set_identifier

    def retrieve_ip_set(self) -> str:
        """ Retrieves the IP set from AWS WAFv2 """

        # Get IP set
        response = self.boto_wafv2_client.get_ip_set(Name=self.ip_set_blocked_name, Scope=self.ip_set_blocked_scope,
                                                     Id=self.ip_set_blocked_identifier)

        return response

    def update_ip_set(self, new_block_list) -> None:
        """ Updates the IP set with a new IP set (block list) """

        # Get reponse for locktoken
        wafv2_response = self.boto_wafv2_client.get_ip_set(Name=self.ip_set_blocked_name, Scope=self.ip_set_blocked_scope,
                                                           Id=self.ip_set_blocked_identifier)
        # Get locktoken
        locktoken = wafv2_response['LockToken']

        # Update current IP Set
        self.boto_wafv2_client.update_ip_set(Name=self.ip_set_blocked_name, Scope=self.ip_set_blocked_scope,
                                             Id=self.ip_set_blocked_identifier,
                                             Addresses=new_block_list, LockToken=locktoken)
