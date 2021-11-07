"""
DELL EMC ECS SAML Assertion Demo.
"""
import logging
import os
import json

# Constants
BASE_CONFIG = 'BASE'                                          # Base Configuration Section
AWS_CONNECTION_CONFIG = 'AWS_CONFIGURATION'                   # AWS Configuration Section
SAML_IDP_CONFIGURATION = 'SAML_IDP'                           # SAML Configuration Section


class InvalidConfigurationException(Exception):
    pass


class ECSSAMLConfiguration(object):
    def __init__(self, config, tempdir):

        if config is None:
            raise InvalidConfigurationException("No file path to the ECS SAML Demo Module configuration provided")

        if not os.path.exists(config):
            raise InvalidConfigurationException("The ECS SAML Demo Module configuration "
                                                "file path does not exist: " + config)
        if tempdir is None:
            raise InvalidConfigurationException("No path for temporary file storage provided")

        # Store temp file storage path to the configuration object
        self.tempfilepath = tempdir

        # Attempt to open configuration file
        try:
            with open(config, 'r') as f:
                parser = json.load(f)
        except Exception as e:
            raise InvalidConfigurationException("The following unexpected exception occurred in the "
                                                "ECS SAML Demo Module attempting to parse "
                                                "the configuration file: " + e.message)

        # Set logging level
        logging_level_raw = parser[BASE_CONFIG]['logging_level']
        self.logging_level = logging.getLevelName(logging_level_raw.upper())

        # Grab AWS settings and validate
        self.aws_region = parser[AWS_CONNECTION_CONFIG]['region']
        self.aws_output = parser[AWS_CONNECTION_CONFIG]['output']
        self.aws_endpoint = parser[AWS_CONNECTION_CONFIG]['endpoint']

        # Validate AWS settings
        if not self.aws_endpoint:
            raise InvalidConfigurationException("The IAM Endpoint is not configured in the module configuration")

        # Grab SAML IDP Settings
        self.saml_idp_url = parser[SAML_IDP_CONFIGURATION]['idp_sso_url']

        # Validate logging level
        if logging_level_raw not in ['debug', 'info', 'warning', 'error']:
            raise InvalidConfigurationException(
                "Logging level can be only one of ['debug', 'info', 'warning', 'error']")

