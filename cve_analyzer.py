import logging
import requests
import json
import os
import argparse
from dotenv import load_dotenv
from prompt import cve_prompt, create_user_prompt # Import create_user_prompt
from invoke_llm import invoke_gemini

load_dotenv()

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load the VulDB API key from environment variables
vuldb_api_key = os.environ.get('VULDB_API_KEY') # Renamed for clarity

def nist_check(cve_id):
    """
    Checks the NIST database for information about a given CVE ID.
    """
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
    logger.info(f"Querying NIST for CVE: {cve_id}")

    try:
        response = requests.get(url=url, timeout=10)
        response.raise_for_status()
        json_response = response.json()
        total_result = json_response.get('totalResults', 0)
        
        logger.info(f"NIST query for {cve_id} returned {total_result} results")
        return total_result, json_response

    except requests.exceptions.RequestException as e:
        logger.error(f"Error during NIST request for {cve_id}: {str(e)}")
        return 0, {}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON response from NIST for {cve_id}: {str(e)}")
        return 0, {}
    except Exception as e:
        logger.error(f"Unexpected error during NIST check for {cve_id}: {str(e)}")
        return 0, {}

def extract_nist_context(nist_data, cve_id):
    """Extracts relevant context from NIST NVD JSON data."""
    context_parts = [f"NIST Data for {cve_id}:"]
    try:
        vuln = nist_data.get('vulnerabilities', [])[0].get('cve', {})

        # Description
        description = vuln.get('descriptions', [{}])[0].get('value')
        if description:
            context_parts.append(f"Description: {description}")

        # CVSS Metrics (v3.1 preferred, fallback to v2)
        metrics = vuln.get('metrics', {})
        cvss_v31 = metrics.get('cvssMetricV31')
        cvss_v2 = metrics.get('cvssMetricV2')
        if cvss_v31:
            metric = cvss_v31[0].get('cvssData', {})
            context_parts.append(f"Impact (CVSS v3.1): Base Score {metric.get('baseScore')}, Severity {metric.get('baseSeverity')}, Vector {metric.get('vectorString')}")
        elif cvss_v2:
            metric = cvss_v2[0].get('cvssData', {})
            context_parts.append(f"Impact (CVSS v2.0): Base Score {metric.get('baseScore')}, Severity {cvss_v2[0].get('baseSeverity')}, Vector {metric.get('vectorString')}")

        # Affected Configurations (CPEs) - Summarize products
        configs = vuln.get('configurations', [])
        affected_products = set()
        for config in configs:
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    cpe_uri = cpe_match.get('criteria', '')
                    # Extract product and vendor from CPE URI (basic parsing)
                    parts = cpe_uri.split(':')
                    if len(parts) > 4:
                        product = parts[4].replace('_', ' ').title()
                        vendor = parts[3].replace('_', ' ').title()
                        affected_products.add(f"{vendor} {product}")
        if affected_products:
             context_parts.append(f"Affected Products Mentioned: {', '.join(sorted(list(affected_products)))}")
        else:
             context_parts.append("Affected Products Mentioned: Check configurations for details.")


        # References
        references = vuln.get('references', [])
        ref_urls = [ref.get('url') for ref in references if ref.get('url')]
        if ref_urls:
            context_parts.append(f"References: {', '.join(ref_urls)}")

        return "\n".join(context_parts)

    except (IndexError, KeyError, TypeError) as e:
        logger.error(f"Error parsing NIST data for {cve_id}: {e}")
        return f"Error parsing NIST data for {cve_id}. Raw data might be incomplete or malformed."


def vuldb_check(vuldb_id):
    """
    Query VulDB API.
    """
    if not vuldb_api_key:
        logger.error("VULDB_API_KEY not found in environment variables.")
        return {}, 0 # Return empty dict and 0 tokens

    url = 'https://vuldb.com/?api'
    headers = {
        'User-Agent': 'VulDB API Advanced Python Demo Agent'
    }
    data = {
        'recent': 1,
        'details': 1,
        'id': vuldb_id
    }

    headers['X-VulDB-ApiKey'] = vuldb_api_key
    logger.info(f"Attempting VulDB query for ID: {vuldb_id}.")

    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        result = response.json()

        # Check if the key is valid/has tokens remaining
        response_info = result.get('response', {})
        if response_info.get('error'):
             logger.error(f"VulDB API returned an error: {response_info.get('error')}")
             return {}, 0
        
        remaining_tokens = response_info.get('remaining', 0)
        if remaining_tokens is not None: # Check explicitly for None in case 0 is valid
             logger.info(f"VulDB query successful. Remaining tokens: {remaining_tokens}")
             return result, remaining_tokens
        else:
             # Handle cases where 'remaining' might be missing but no error is reported
             logger.warning("VulDB response structure might have changed or key is invalid (no 'remaining' field).")
             return result, 0 # Assume 0 tokens if field is missing but no error

    except requests.exceptions.RequestException as e:
        logger.error(f"VulDB API request failed: {str(e)}")
        return {}, 0
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON response from VulDB: {str(e)}")
        return {}, 0
    except Exception as e:
        logger.error(f"Unexpected error during VulDB check: {str(e)}")
        return {}, 0

def extract_vuldb_context(vuldb_data, vuldb_id):
    """Extracts relevant context from VulDB JSON data."""
    context_parts = [f"VulDB Data for ID {vuldb_id}:"]
    try:
        result = vuldb_data.get('result', [{}])[0]
        entry = result.get('entry', {})
        vulnerability = result.get('vulnerability', {})
        advisory = result.get('advisory', {})
        countermeasure = result.get('countermeasure', {})
        source = result.get('source', {})

        # Description / Title / Summary
        title = entry.get('title')
        summary = advisory.get('summary')
        if title: context_parts.append(f"Title: {title}")
        if summary: context_parts.append(f"Summary: {summary}")

        # Affected Product
        product = vulnerability.get('product')
        if product: context_parts.append(f"Affected Product: {product}")

        # Impact / Severity
        cvss = vulnerability.get('cvss', {})
        cvss_base_score = cvss.get('basescore')
        cvss_vector = cvss.get('vector')
        severity = vulnerability.get('risk', {}).get('name')
        impact_parts = []
        if severity: impact_parts.append(f"Severity: {severity}")
        if cvss_base_score: impact_parts.append(f"CVSS Base Score: {cvss_base_score}")
        if cvss_vector: impact_parts.append(f"CVSS Vector: {cvss_vector}")
        if impact_parts: context_parts.append(f"Impact: {'; '.join(impact_parts)}")

        # Mitigations / Countermeasures
        patch = countermeasure.get('patch')
        workaround = countermeasure.get('workaround')
        mitigation_parts = []
        if patch: mitigation_parts.append(f"Patch: {patch}")
        if workaround: mitigation_parts.append(f"Workaround: {workaround}")
        if mitigation_parts: context_parts.append(f"Mitigation: {'; '.join(mitigation_parts)}")

        # References
        references = []
        cve_id_ref = advisory.get('cve', {}).get('id')
        if cve_id_ref: references.append(f"CVE ID: {cve_id_ref}")
        vendor_ref = source.get('vendor', {}).get('reference')
        if vendor_ref: references.append(f"Vendor Reference: {vendor_ref}")
        other_refs = source.get('references', [])
        for ref in other_refs:
            if ref.get('url'): references.append(ref.get('url'))
        if references: context_parts.append(f"References: {', '.join(references)}")

        return "\n".join(context_parts)

    except (IndexError, KeyError, TypeError) as e:
        logger.error(f"Error parsing VulDB data for {vuldb_id}: {e}")
        return f"Error parsing VulDB data for {vuldb_id}. Raw data might be incomplete or malformed."


def cve_analysis(cve_id, vuldb_id=None):
    """
    Perform CVE analysis using NIST and optionally VulDB data sources.
    Extracts context and uses an LLM for structured analysis.
    """
    logger.info(f"Starting CVE analysis for CVE ID: {cve_id}" + (f", VulDB ID: {vuldb_id}" if vuldb_id else ""))

    context = ""
    source_used = ""

    # 1. Try NIST
    total_result, nist_data = nist_check(cve_id)
    if total_result > 0 and nist_data:
        logger.info("Found data in NIST NVD.")
        context = extract_nist_context(nist_data, cve_id)
        source_used = "NIST"
    # 2. Try VulDB if NIST failed or no VulDB ID provided initially
    elif vuldb_id:
        logger.info(f"NIST data not found or empty for {cve_id}. Trying VulDB with ID: {vuldb_id}")
        vuldb_data, remaining_tokens = vuldb_check(vuldb_id)
        if vuldb_data and remaining_tokens > 0:
            logger.info("Found data in VulDB.")
            context = extract_vuldb_context(vuldb_data, vuldb_id)
            source_used = "VulDB"
        else:
            logger.warning(f"Failed to retrieve data from VulDB for ID: {vuldb_id}")
    else:
         logger.warning(f"NIST data not found for {cve_id} and no VulDB ID provided.")


    # 3. If context was extracted, call LLM
    if context:
        logger.info(f"Sending extracted context from {source_used} to LLM for analysis.")
        system_prompt = cve_prompt()
        user_prompt = create_user_prompt(context) # Use the helper

        # Using gemini-1.5-flash as it's generally available and capable
        # Adjust model, token output, temp as needed
        analysis_result = invoke_gemini(
            model='gemini-2.0-flash', # Use a specific model identifier
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            token_output=2000,
            temperature=0.1 # Lower temp for more deterministic JSON
        )

        # Parse the JSON string returned by the reverted invoke_gemini
        try:
            # Clean potential markdown ```json ... ``` markers if present
            if analysis_result.strip().startswith("```json"):
                analysis_result = analysis_result.strip()[7:-3].strip()
            elif analysis_result.strip().startswith("```"):
                 analysis_result = analysis_result.strip()[3:-3].strip()

            parsed_result = json.loads(analysis_result)
            logger.info("Successfully parsed JSON response from LLM text output.")
            return parsed_result
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON from LLM response: {e}")
            logger.error(f"Received text: {analysis_result}")
            return {"error": "Invalid JSON response received from LLM.", "raw_response": analysis_result}
        except Exception as e: # Catch other potential errors during parsing
             logger.error(f"Error processing LLM response: {e}")
             return {"error": f"Error processing LLM response: {e}", "raw_response": analysis_result}

    else:
        logger.error(f"Failed to retrieve data from any source for CVE: {cve_id}")
        return {"error": f"Unable to retrieve CVE data for {cve_id} from available sources."}

def format_analysis_output(analysis_dict, cve_id):
    """Formats the analysis dictionary into a human-readable string."""
    if not isinstance(analysis_dict, dict) or 'error' in analysis_dict:
        # Handle error case or non-dict input
        error_message = analysis_dict.get('error', 'Unknown error or invalid format')
        raw_response = analysis_dict.get('raw_response', '')
        return f"--- Analysis Failed for {cve_id} ---\nError: {error_message}\nRaw Response: {raw_response}\n"

    output = [f"--- CVE Analysis Report for {cve_id} ---"]

    # Description
    output.append("\n[Description]")
    output.append(analysis_dict.get('description', 'N/A'))

    # Impact
    output.append("\n[Impact / Severity]")
    output.append(analysis_dict.get('impact', 'N/A'))

    # Affected Products
    output.append("\n[Affected Products / Versions]")
    affected = analysis_dict.get('affected_products', [])
    if affected:
        for item in affected:
            output.append(f"- {item}")
    else:
        output.append("N/A")

    # Mitigations
    output.append("\n[Mitigations / Recommendations]")
    output.append(analysis_dict.get('mitigations', 'N/A'))

    # References
    output.append("\n[References]")
    references = analysis_dict.get('references', [])
    if references:
        for item in references:
            output.append(f"- {item}")
    else:
        output.append("N/A")

    output.append("\n--------------------------------------")
    return "\n".join(output)


# Example Usage Block
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze a CVE using NIST and/or VulDB.")
    parser.add_argument("cve_id", help="The CVE ID to analyze (e.g., CVE-2023-12345)")
    parser.add_argument("--vuldb_id", help="Optional VulDB ID associated with the CVE", default=None)
    args = parser.parse_args()

    logger.info(f"--- Starting Analysis for {args.cve_id} ---")
    result = cve_analysis(args.cve_id, args.vuldb_id)

    # Format and print the result
    formatted_output = format_analysis_output(result, args.cve_id)
    print(formatted_output)

    if isinstance(result, dict) and 'error' in result:
         logger.error(f"Analysis for {args.cve_id} completed with errors.")
    else:
         logger.info(f"--- Analysis Complete for {args.cve_id} ---")
