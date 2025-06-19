"""
example.py
Simple demo:
  1. Read API settings from config.json.
  2. Get an OAuth token.
  3. Call /projects and print the results.
"""
#Standard Library
import logging
import sys
#Third-party
import requests
#Local
from utils.generate_oauth_token import load_config, generate_oauth_token


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# Load configuration from config.json
CONFIG = load_config()
BASE_API_URL = CONFIG.get("api_url")
REQUEST_TIMEOUT = 10  # seconds

if not BASE_API_URL:
    sys.exit("api_url missing in config.json")

# Get a dict of projects from the API
def get_projects(headers: dict) -> dict:
    """
        Retrieve a list of projects from the configured API endpoint.

        Sends a GET request to the /projects endpoint using the provided headers.
        Includes optional query parameters (e.g., limit) to control the result size.

        Args:
            headers (dict): HTTP headers used for authentication or other request requirements.

        Returns:
            dict: A dictionary containing the list of projects if successful,
                or an empty dictionary if the request fails.

        Logs:
            - Error details if the request fails due to network issues or invalid responses.
    """
    
    url = f"{BASE_API_URL}/projects"
    #Example for Params
    params = {
        "limit": 10,  # Example parameter to limit the number of projects returned
    }
    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT,params=params)
        response.raise_for_status()
        return response.json().get("projects", [])
    except requests.RequestException as err:
        log.error(f"Project request failed: {err}")
        return {}

def display_projects(projects: list) -> None:
    """
        Log and display a list of project identifiers and names.

        Iterates through the provided list of project dictionaries and logs each project's
        ID and name. If the list is empty, a warning is logged instead.

        Args:
            projects (list): A list of dictionaries, each representing a project
                            with keys such as 'id' and 'name'.

        Logs:
            - A warning if the project list is empty.
            - An info message with the total number of projects retrieved.
            - An info message for each project displaying its ID and name.
    """
    if not projects:
        log.warning("No projects found.")
        return

    log.info(f"{len(projects)} project(s) retrieved:")
    for p in projects:
        log.info(f"- {p.get('id')}: {p.get('name')}")

def get_findings(headers: dict, scan_id: str) -> dict:
    """
        Retrieve a list of scan findings from the /results API endpoint.

        Sends a GET request with the provided headers and query parameters such as
        scan ID and result limit. Returns the list of findings (vulnerabilities/issues)
        if the request is successful, or an empty dictionary if it fails.

        Args:
            headers (dict): HTTP headers used for authentication and API access.

        Returns:
            dict: A dictionary containing a list of findings under the "results" key,
                or an empty dictionary on failure.

        Notes:
            - The 'scan-id' parameter must be set to retrieve specific scan results.
            - The 'limit' parameter can be increased or paginated using an 'offset' param
            if more results are needed.

        Logs:
            - An error message if the API request fails or raises an exception.
    """
    url = f"{BASE_API_URL}/results"
    #Example for Params
    params = {
        "scan-id": scan_id,  # Replace with actual scan ID
        "limit": 10 # change this or loop with offset param to get more results
    }
    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT,params=params)
        response.raise_for_status()
        json_response = response.json()
        return json_response.get("results", {})
    except requests.RequestException as err:
        log.error(f"Project request failed: {err}")
        return {}
    
    
def filter_findings(findings: list) -> list:
    """
    Deduplicate a list of findings based on the 'similarityId' key.

    Args:
        findings (list): A list of dictionaries representing findings,
                         each expected to have a 'similarityId' key.

    Returns:
        list: A list of unique findings based on 'similarityId'.

    Logs:
        - An info message when a duplicate finding is skipped.
        - A warning if the input is not a list or contains invalid entries.
    """
    if not isinstance(findings, list):
        log.warning("Invalid input: 'findings' is not a list.")
        return []

    seen = set()
    deduped = []

    for i, finding in enumerate(findings):
        if not isinstance(finding, dict):
            log.warning(f"Skipping invalid finding at index {i} (not a dict).")
            continue

        sim_id = finding.get("similarityId")
        if not sim_id:
            log.warning(f"Skipping finding at index {i} with missing 'similarityId'.")
            continue

        if sim_id not in seen:
            seen.add(sim_id)
            deduped.append(finding)
        else:
            # log.info(f"Duplicate finding skipped (similarityId: {sim_id})")
            pass # uncomment the above line to log duplicates

    return deduped


def output_findings_results(findings: list, output_file: str = "output.txt") -> None:
    """
        Display and optionally write remediation recommendations to a file.

        Iterates through a list of security findings and formats relevant remediation
        information such as scan type, issue description, severity, and recommendations.
        The results are written to the specified output file in a readable format.

        Args:
            findings (list): A list of dictionaries representing findings. Each dictionary
                            is expected to contain keys such as 'type', 'description',
                            'severity', and a nested 'data' dict with 'issueType' and
                            'recommendations'.
            output_file (str, optional): Path to the output file to write the recommendations.
                                        Defaults to "output.txt".

        Returns:
            None

        Logs:
            - A warning if no findings are provided.
            - An info message when recommendations are successfully written to a file.
    """

    
    if not findings:
        log.warning("No remediation recommendations found.")
        return

    output_lines = [f"{len(findings)} remediation recommendation(s) retrieved:\n"]

    for f in findings:
        data = f.get("data", {})
        output_lines.append(
            f"""Scan Type      : {f.get('type', '')}
        Description    : {f.get('description', '')}
        Issue Type     : {data.get('issueType', '')}
        Severity       : {f.get('severity', '')}
        Recommendations: {data.get('recommendations', 'N/A')}
        {'-' * 50}"""
        )

    output = "\n".join(output_lines)
    # log.info("\n" + output)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output)
        log.info(f"Remediation recommendations written to: {output_file}")

def main():
    token = generate_oauth_token(CONFIG)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if not token:
        log.error("Could not obtain OAuth token.")
        return

    log.info(f"OAuth token obtained: ***{token[-8:]}")  # Log only the last 4 characters for security
    # projects = get_projects(headers)
    # display_projects(projects)
    scan_ids = ["<Add Scan IDs here>"]  # Replace with actual scan IDs or loop through a list of scan IDs
    all_findings = []
    #Loop through each scan ID to get findings
    for scan_id in scan_ids:
        findings = get_findings(headers=headers, scan_id=scan_id)
        all_findings.append(findings)
    all_findings = [item for sublist in all_findings for item in sublist]  # Flatten the list of findings
    #Filter the findings to remove duplicates
    filtered_all_findings = filter_findings(all_findings)
    
    output_findings_results(filtered_all_findings)
    
if __name__ == "__main__":
    main()
