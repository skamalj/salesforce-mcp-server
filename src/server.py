import os
import urllib.parse
import requests
import boto3
import json
from typing import Optional, Literal
from mcp.server.fastmcp import FastMCP
from logger import get_logger  # Assuming logger.py exists and exports `logger`

domain = os.environ.get("SALESFORCE_DOMAIN")
client_id = os.environ.get("SALESFORCE_CLIENT_ID")
redirect_uri = os.environ.get("SALESFORCE_REDIRECT_URI")
table_name = os.getenv("SF_DDB_TABLE")
api_version = os.getenv("SF_API_VERSION", "v60.0")
logger = get_logger(__name__)

mcp = FastMCP("Salesforce", stateless_http=True)

@mcp.resource("salesforce://domain")
def get_salesforce_domain() -> str:
    if not domain:
        logger.error("SALESFORCE_DOMAIN environment variable is not set.")
        raise EnvironmentError("SALESFORCE_DOMAIN environment variable is not set.")
    logger.debug("Retrieved Salesforce domain.")
    return domain


@mcp.tool()
def generate_salesforce_oauth_url(profile_id: str) -> str:
    """
    Generates a Salesforce OAuth2 authorization URL for a user.
    
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
        logger.error("Missing required environment variables for OAuth URL generation.")
        raise ValueError("Missing required environment variables.")

    base_url = f"https://{domain}/services/oauth2/authorize"
    query_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "api",
        "state": f"profile:{profile_id}"
    }

    url = f"{base_url}?{urllib.parse.urlencode(query_params)}"
    logger.info(f"Generated OAuth URL for profile_id={profile_id}")
    return url


@mcp.tool()
def execute_salesforce_soql(soql_query: str, profile_id: str) -> list[dict]:
    """
    Executes a SOQL query against Salesforce using credentials fetched from DynamoDB.

    Args:
        soql_query (str): The SOQL query to execute.
        profile_id (str): The ID used to look up Salesforce credentials in DynamoDB.
                          This is NOT the Salesforce UserId. Use rest api tool to get userid to refer to the Salesforce user associated with the access_token retrieved via profile_id.

    Returns:
        List[dict]: Records from the query result.

    Raises:
        Exception: If credentials are missing or query fails.
    """
    logger.debug(f"Executing SOQL query={soql_query} for profile_id={profile_id}")
    if not table_name:
        logger.error("Missing SF_DDB_TABLE in environment variables.")
        raise EnvironmentError("Missing SF_DDB_TABLE in environment variables.")

    ddb = boto3.resource("dynamodb")
    table = ddb.Table(table_name)

    response = table.get_item(Key={"wa_id": profile_id})
    if "Item" not in response:
        logger.error(f"No record found in DynamoDB for wa_id: {profile_id}")
        raise Exception(f"No record found in DynamoDB for wa_id: {profile_id}")

    item = response["Item"]
    access_token = item.get("access_token")
    instance_url = item.get("instance_url")

    if not access_token or not instance_url:
        logger.error(f"Missing credentials for wa_id: {profile_id}")
        raise Exception(f"Missing access_token or instance_url for wa_id: {profile_id}")

    url = f"{instance_url}/services/data/{api_version}/query"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    params = {"q": soql_query}

    resp = requests.get(url, headers=headers, params=params)

    if resp.status_code != 200:
        logger.error(f"Salesforce query failed: {resp.status_code} - {resp.text}")
        raise Exception(f"Salesforce query failed: {resp.status_code} - {resp.text}")

    logger.info(f"SOQL query successful for profile_id={profile_id}")
    return resp.json().get("records", [])


@mcp.tool()
def execute_salesforce_rest(object_type: str, operation: Literal["create", "update", "get"],  profile_id: str, data: dict ={},record_id: Optional[str] = None) -> dict:
    """
    Create, update, or fetch a Salesforce resource using the REST API.

    Args:
        object_type (str): 
            For "create"/"update": Salesforce object name (e.g., "Opportunity", "Account").
            For "get": 
            - Full REST path relative to `/services/data/<version>/`, 
            - Or the literal string `"userinfo"` to retrieve authenticated user info from the Salesforce OAuth2 `/services/oauth2/userinfo` endpoint.
        operation (str): One of "create", "update", or "get".
        profile_id (str): wa_id used to retrieve Salesforce credentials from DynamoDB.
        data (dict): 
            For "create" and "update": Field values to set.
            For "get": Ignored (but must be provided due to tool signature).
        record_id (str, optional): Required for "update" to specify the record to modify.

    Returns:
        dict: Salesforce API response. For "get", returns full response body. For "create"/"update", success status or created object.

    Raises:
        Exception: If credentials are missing or API request fails.
    """
    logger.debug(f"REST call: {operation} {object_type} for profile_id={profile_id}")
    if not table_name:
        logger.error("Missing SF_DDB_TABLE env variable.")
        raise EnvironmentError("Missing SF_DDB_TABLE env variable.")

    ddb = boto3.resource("dynamodb")
    table = ddb.Table(table_name)
    response = table.get_item(Key={"wa_id": str(profile_id)})

    if "Item" not in response:
        logger.error(f"No record found for wa_id: {profile_id}")
        raise Exception(f"No record found for wa_id: {profile_id}")

    item = response["Item"]
    access_token = item.get("access_token")
    instance_url = item.get("instance_url")

    if not access_token or not instance_url:
        logger.error(f"Missing access_token or instance_url for wa_id: {profile_id}")
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
            logger.error("record_id is required for update.")
            raise ValueError("record_id is required for update.")
        url = f"{instance_url}/services/data/{api_version}/sobjects/{object_type}/{record_id}"
        resp = requests.patch(url, headers=headers, json=data)
    elif operation == "get":
        # If object_type is a known alias for user info, call the OAuth2 userinfo endpoint
        if object_type == "userinfo":
            url = f"{instance_url}/services/oauth2/userinfo"
        else:
            url = f"{instance_url}/services/data/{api_version}/{object_type}"
        resp = requests.get(url, headers=headers)
    else:
        logger.error(f"Unsupported operation: {operation}")
        raise ValueError(f"Unsupported operation: {operation}")

    if resp.status_code not in (200, 201, 204):
        logger.error(f"Salesforce API failed: {resp.status_code} - {resp.text}")
        raise Exception(f"Salesforce API failed: {resp.status_code} - {resp.text}")

    logger.info(f"Salesforce {operation} operation successful for {object_type} and profile_id={profile_id}")
    return resp.json() if resp.content else {"success": True}


@mcp.tool()
def send_whatsapp_message(recipient, message):
    """
    Sends a WhatsApp message using the Meta API.

    :param recipient: The recipient's phone number.
    :return: The JSON response from the API call.
    """
    logger.debug(f"Sending WhatsApp message to {recipient}")
    access_token = os.getenv("WHATSAPP_API_TOKEN")
    whatsapp_number_id = os.getenv("WHATSAPP_NUMBER_ID")

    if not access_token:
        logger.error("Failed to retrieve WhatsApp API access token.")
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
    logger.info(f"WhatsApp message sent to {recipient}")
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
    logger.debug("Preparing to send email via SES.")
    try:
        email_data = json.loads(email_json)
        to_email = email_data.get("to_email")
        subject = email_data.get("subject", "No Subject")
        body = email_data.get("body", "")
        is_html = email_data.get("is_html", False)

        if not to_email or not body:
            logger.warning("Missing required fields for email.")
            return "Error: Missing required fields ('to_email' or 'body')."

        message_body = {"Html": {"Data": body}} if is_html else {"Text": {"Data": body}}
        ses_client = boto3.client("ses")
        FROM_EMAIL = os.getenv("EMAIL_FROM", "agent@mockify.com")

        response = ses_client.send_email(
            Source=FROM_EMAIL,
            Destination={"ToAddresses": [to_email]},
            Message={
                "Subject": {"Data": subject},
                "Body": message_body,
            },
        )
        logger.info(f"Email sent to {to_email} via SES.")
        return f"Email sent successfully! Message ID: {response['MessageId']}"

    except Exception as e:
        logger.error(f"Error sending email via SES: {str(e)}")
        return f"Error sending email: {str(e)}"


@mcp.tool()
def get_weather(location: str):
    logger.debug(f"Getting weather for location: {location}")
    if location.lower() in ["sf", "san francisco"]:
        return "It's 60 degrees and foggy."
    else:
        return "It's 90 degrees and sunny."


@mcp.tool()
def get_coolest_cities():
    logger.debug("Fetching coolest cities.")
    return "nyc, sf"


if __name__ == "__main__":
    logger.info("Starting FastMCP server...")
    mcp.run(transport="streamable-http")
    logger.info("FastMCP server is running.")
