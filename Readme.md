https://aws.amazon.com/blogs/architecture/field-notes-serverless-container-based-apis-with-amazon-ecs-and-amazon-api-gateway/

aws secretsmanager create-secret \
  --name salesforce_credentials \
  --description "Salesforce credentials for ECS service" \
  --secret-string '{
    "SALESFORCE_DOMAIN": "velocity-ruby-3676.my.salesforce.com",
    "SALESFORCE_CLIENT_ID": "3MVG9RGN2EqkAxhIwRqrLvfEeX0YIjALkdiM7b6kxf9me_VCtdg.BKNY54OTRIU1sLUqyekMmjnIpHDhkMqw7",
    "SALESFORCE_REDIRECT_URI": "https://hhtiphxg61.execute-api.ap-south-1.amazonaws.com/Prod/callback/"
  }'
