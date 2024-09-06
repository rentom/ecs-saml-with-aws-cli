# ecs-saml-with-aws-cli
Demo application that will perform an SSO login and then use the AWS CLI to perform the AssumeRoleWith SAML as well as AWS CLI Credential generation

This app was tested with the following installed:
- Python 3.9
  - Requires the following Python modules to be installed:
    - requests
    - bs4
    - lxml
- AWS CLI 2.1.17

If you want to, you can try to avoid that `aws` are making calls to AWS Instance Metadata Service(at 169.254.169.254). with the following environment variable: 
```
export AWS_EC2_METADATA_DISABLED=true
```
