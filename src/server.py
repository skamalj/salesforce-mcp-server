import os
import urllib.parse
import requests
from utils import get_secret
import boto3
import json
from typing import Optional, Literal
from mcp.server.fastmcp import FastMCP

domain = os.environ.get("SALESFORCE_DOMAIN")
client_id = os.environ.get("SALESFORCE_CLIENT_ID")
redirect_uri = os.environ.get("SALESFORCE_REDIRECT_URI")
table_name = os.getenv("SF_DDB_TABLE")
api_version = os.getenv("SF_API_VERSION", "v60.0")

mcp = FastMCP("Salesforce", stateless_http=True)

@mcp.resource("salesforce://domain")
def get_salesforce_domain() -> str:
    """
    Returns the Salesforce domain from environment variables.

    Resource URI:
        salesforce://domain

    Returns:
        str: Salesforce domain (e.g., 'login.salesforce.com')
    """
    if not domain:
        raise EnvironmentError("SALESFORCE_DOMAIN environment variable is not set.")
    return domain


@mcp.tool()
def generate_salesforce_oauth_url(profile_id: str) -> str:
    """
    Generates a Salesforce OAuth2 authorization URL using values from environment variables
    and a provided profile_id.
    
    Env Variables:
    - SALESFORCE_DOMAIN
    - SALESFORCE_CLIENT_ID
    - SALESFORCE_REDIRECT_URI
    
    Args:
        profile_id (str): The user profile ID to be passed in the state parameter.
    
    Returns:
        str: Complete Salesforce OAuth2 URL.
    """

    if not all([domain, client_id, redirect_uri]):
        raise ValueError("Missing required environment variables.")

    base_url = f"https://{domain}/services/oauth2/authorize"
    query_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "api",
        "state": f"profile:{profile_id}"
    }

    return f"{base_url}?{urllib.parse.urlencode(query_params)}"


@mcp.tool()
def execute_salesforce_soql(soql_query: str, profile_id: str) -> list[dict]:
    """
    Executes a SOQL query against Salesforce using credentials fetched from DynamoDB.

    Args:
        soql_query (str): The SOQL query to execute.
        profile_id (str): The wa_id used to look up Salesforce credentials in DynamoDB.

    DynamoDB Table Schema (per item):
        - wa_id (str): Primary key
        - access_token (str)
        - instance_url (str)
        - refresh_token (str, optional)
        - issued_at (int, optional)

    Required environment variables:
        - SF_DDB_TABLE: Name of the DynamoDB table
        - SF_API_VERSION: Optional, defaults to 'v60.0'

    Returns:
        List[dict]: Records from the query result.

    Raises:
        Exception: If credentials are missing or query fails.
    """

    if not table_name:
        raise EnvironmentError("Missing SF_DDB_TABLE in environment variables.")

    # Fetch credentials from DynamoDB
    ddb = boto3.resource("dynamodb")
    table = ddb.Table(table_name)

    response = table.get_item(Key={"wa_id": profile_id})
    if "Item" not in response:
        raise Exception(f"No record found in DynamoDB for wa_id: {profile_id}")

    item = response["Item"]
    access_token = item.get("access_token")
    instance_url = item.get("instance_url")

    if not access_token or not instance_url:
        raise Exception(f"Missing access_token or instance_url for wa_id: {profile_id}")

    # Execute SOQL query
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    url = f"{instance_url}/services/data/{api_version}/query"
    params = {"q": soql_query}

    resp = requests.get(url, headers=headers, params=params)

    if resp.status_code != 200:
        raise Exception(f"Salesforce query failed: {resp.status_code} - {resp.text}")

    return resp.json().get("records", [])

@mcp.tool()
def execute_salesforce_rest(
    object_type: str,
    operation: Literal["create", "update"],
    data: dict,
    profile_id: str,
    record_id: Optional[str] = None
) -> dict:
    """
    Create or update a Salesforce object.

    Args:
        object_type (str): Salesforce object name (e.g., "Opportunity", "Account").
        operation (str): One of "create" or "update".
        data (dict): Fields and values to set.
        profile_id (str): wa_id to look up Salesforce credentials.
        record_id (str, optional): Required for update operation.

    Returns:
        dict: Salesforce API response.

    Raises:
        Exception: On credential or API failure.
    """

    if not table_name:
        raise EnvironmentError("Missing SF_DDB_TABLE env variable.")

    ddb = boto3.resource("dynamodb")
    table = ddb.Table(table_name)
    response = table.get_item(Key={"wa_id": str(profile_id)})

    if "Item" not in response:
        raise Exception(f"No record found for wa_id: {profile_id}")

    item = response["Item"]
    access_token = item.get("access_token")
    instance_url = item.get("instance_url")

    if not access_token or not instance_url:
        raise Exception("Missing access_token or instance_url")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    if operation == "create":
        url = f"{instance_url}/services/data/{api_version}/sobjects/{object_type}/"
        resp = requests.post(url, headers=headers, json=data)

    elif operation == "update":
        if not record_id:
            raise ValueError("record_id is required for update.")
        url = f"{instance_url}/services/data/{api_version}/sobjects/{object_type}/{record_id}"
        resp = requests.patch(url, headers=headers, json=data)

    else:
        raise ValueError(f"Unsupported operation: {operation}")

    if resp.status_code not in (200, 201, 204):
        raise Exception(f"Salesforce API failed: {resp.status_code} - {resp.text}")

    return resp.json() if resp.content else {"success": True}

@mcp.tool()
def send_whatsapp_message(recipient, message):
    """
    Sends a WhatsApp message using the Meta API.

    :param recipient: The recipient's phone number.
    :return: The JSON response from the API call.
    """
    access_token = get_secret("WhatsAppAPIToken")  # Fetch token from Secrets Manager
    whatsapp_number_id = get_secret("WhatsappNumberID")  # Fetch WhatsApp number ID from Secrets Manager
    if not access_token:
        print("Failed to retrieve access token.")
        return None
    
    url = f"https://graph.facebook.com/v22.0/{whatsapp_number_id}/messages"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "messaging_product": "whatsapp",
        "to": recipient,
        "type": "text",
        "text": {"body": message}
    }
    
    response = requests.post(url, headers=headers, json=payload)
    return response.json()


@mcp.tool()
def send_email_via_ses(email_json: str):
    """
    Sends an email using AWS SES.

    Expected JSON format:
    {
        "to_email": "recipient@example.com",
        "subject": "Subject Line",
        "body": "Email body content",
        "is_html": false  # Set to true to enable HTML formatting for a better-looking report
    }

    Note:
    For visually appealing, well-formatted reports (e.g., tables, styled text), set "is_html" to true and use HTML in the "body".

    :param email_json: JSON string containing email details.
    :return: Response message indicating success or failure.
    """
    try:
        # Parse JSON input
        email_data = json.loads(email_json)
        to_email = email_data.get("to_email")
        subject = email_data.get("subject", "No Subject")
        body = email_data.get("body", "")
        is_html = email_data.get("is_html", False)

        # Ensure required fields are present
        if not to_email or not body:
            return "Error: Missing required fields ('to_email' or 'body')."

        # Construct email body (HTML or plain text)
        message_body = {"Html": {"Data": body}} if is_html else {"Text": {"Data": body}}
        ses_client = boto3.client("ses")
        FROM_EMAIL = os.getenv("EMAIL_FROM", "agent@mockify.com")
        # Send email via AWS SES
        response = ses_client.send_email(
            Source=FROM_EMAIL,
            Destination={"ToAddresses": [to_email]},
            Message={
                "Subject": {"Data": subject},
                "Body": message_body,
            },
        )
        return f"Email sent successfully! Message ID: {response['MessageId']}"

    except Exception as e:
        return f"Error sending email: {str(e)}"


@mcp.tool()
def get_weather(location: str):
    """Call to get the current weather."""
    if location.lower() in ["sf", "san francisco"]:
        return "It's 60 degrees and foggy."
    else:
        return "It's 90 degrees and sunny."


@mcp.tool()
def get_coolest_cities():
    """Get a list of coolest cities"""
    return "nyc, sf"

if __name__ == "__main__":
    print("Starting server...")
    mcp.run(transport="streamable-http")
    print("Server is running...")