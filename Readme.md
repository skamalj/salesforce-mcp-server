# Salesforce Model Context Protocol (MCP) Implementation

This project implements a Model Context Protocol (MCP) server for Salesforce integration using AWS serverless infrastructure. It provides a robust interface for executing Salesforce operations and managing OAuth2 authentication flows.

## Overview

The implementation consists of three main components:

1. **MCP Server (server.py)**: FastMCP-based server implementing Salesforce operations
2. **Network Infrastructure (network.yaml)**: AWS CloudFormation template for VPC and networking
3. **Service Infrastructure (service.yaml)**: AWS CloudFormation template for ECS Fargate deployment

## Features

- Salesforce OAuth2 authentication flow
- SOQL query execution
- REST API operations (create/update/get)
- WhatsApp message integration
- Email sending via AWS SES
- Weather information endpoints (mock)
- AWS service integration (DynamoDB, Secrets Manager, ECS)

## Prerequisites

- AWS Account with appropriate permissions
- AWS SAM CLI installed
- Salesforce Developer Account
- Required environment variables configured in AWS Secrets Manager

## Environment Variables

### Salesforce Configuration
- `SALESFORCE_DOMAIN`
- `SALESFORCE_CLIENT_ID`
- `SALESFORCE_REDIRECT_URI`
- `SF_DDB_TABLE`
- `SF_API_VERSION`

### WhatsApp Configuration
- `WHATSAPP_API_TOKEN`
- `WHATSAPP_NUMBER_ID`

## Infrastructure Setup

1. Deploy the network stack:
```bash
sam deploy --template-file network.yaml --stack-name mcp-network-stack --capabilities CAPABILITY_NAMED_IAM
```


2. Deploy the service stack:
```bash
sam build
sam deploy --template-file service.yaml --stack-name mcp-service-stack --capabilities CAPABILITY_NAMED_IAM
```


## MCP Tools

### Salesforce Operations
- `generate_salesforce_oauth_url`: Generate OAuth2 authorization URL
- `execute_salesforce_soql`: Execute SOQL queries
- `execute_salesforce_rest`: Perform REST API operations

### Communication Tools
- `send_whatsapp_message`: Send WhatsApp messages
- `send_email_via_ses`: Send emails using AWS SES


## Logging

The application uses CloudWatch Logs with the following configuration:
- Log Group: `/ecs/mcp-salesforce-server`
- Retention: 7 days
- Log Level: Configurable via `LOG_LEVEL` environment variable

## Service Discovery

- Private DNS Namespace: `mcp.local`
- Public DNS Namespace: `mcp.fauxdata.in`

## License

This project is proprietary and confidential.


