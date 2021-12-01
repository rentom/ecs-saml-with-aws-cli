# ecs-saml-aws-cli configuration
----------------------------------------------------------------------------------------------
ecs-saml-aws-cli is a PYTHON application that demonstrates using DELL EMC's
ECS Secure Token Service (STS) to generate temporary credentials using a SAML Assertion.  In
this case the AssumeRoleWithSAML call will be performed by the AWS CLI

The application will then use the AWS CLI to create / update an AWS profile with the temporary
credentials

The demo uses a configuration file that allows the user to pre-configure:

the ECS where the STS API calls will be made

We've provided a sample configuration file:

- ecs_saml_demo_config.sample: Change file suffix from .sample to .json and configure as needed
  This contains the tool configuration for ECS and database connection, logging level, etc. Here
  is the sample configuration:
  
  `BASE`:
  
      logging_level - The default is "info" but it can be set to "debug" to generate a LOT of details
      datastore - This is a placeholder for future datastores.  At the moment it's set to "influx"

  `SAML_IDP`:
      
      idp_sso_url = This is the URL of the SSO for the Identity Provider

  `AWS_CONFIGURATION`
    
      region - This is the AWS Region
      output - This is the output format for AWS CLI commands
      endpoint - This is the endpoint that will be used with the AWS CLI commands to override to ECS
      token_session_duration_seconds - This is the duration in seconds of the temporary token provided by the secure token service (STS)

