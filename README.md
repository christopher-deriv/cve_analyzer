# CVE Analyzer with Gemini LLM

This project provides tools to analyze Common Vulnerabilities and Exposures (CVEs) by fetching data from public sources like NIST NVD and VulDB, and then using Google's Gemini LLM to generate a structured analysis report in JSON format using Python scripts.

## Features

*   Fetches CVE details from NIST NVD based on CVE ID.
*   Optionally fetches vulnerability details from VulDB based on VulDB ID.
*   Prioritizes NIST data but falls back to VulDB if NIST data is unavailable or a VulDB ID is provided.
*   Extracts key information (description, affected products, impact, mitigations, references) from the fetched data.
*   Uses the Gemini LLM (via the `google-genai` library) to process the extracted context and generate a structured JSON analysis.
*   Provides a command-line script (`cve_analyzer.py`) for execution.
*   Handles API key management using `.env` files.

## Setup

### Prerequisites

*   Python 3.x
*   Access to Google AI Studio or Google Cloud Vertex AI for a Gemini API key.
*   (Optional) A VulDB API key for accessing VulDB data.

### Installation

1.  **Clone the repository (optional):**
    ```bash
    git clone <your-repo-url>
    cd <your-repo-directory>
    ```

2.  **Install dependencies:**
    Install the required packages using pip:
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: `requirements.txt` includes `python-dotenv`, `requests`, `google-genai`)*

### API Key Configuration

*   Create a file named `.env` in the project's root directory (you can rename the provided `.env.example` file).
*   Add your API keys to the `.env` file:
    ```dotenv
    GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
    VULDB_API_KEY="YOUR_VULDB_API_KEY" 
    ```

## Usage

Run the `cve_analyzer.py` script from your terminal, providing the CVE ID as a mandatory argument and optionally the corresponding VulDB ID.

```bash
python cve_analyzer.py <CVE_ID> [--vuldb_id <VULDB_ID>]
```

**Examples:**

*   Analyze using only NIST data (if available):
    ```bash
    python cve_analyzer.py CVE-2023-38545 
    ```
*   Analyze using NIST, or VulDB if NIST fails or if you want to prioritize VulDB data for a specific ID:
    ```bash
    python cve_analyzer.py CVE-2024-27198 --vuldb_id 255462
    ```

The script will print the formatted analysis report to the console.

## File Structure

*   `.env.example`: Example environment file template.
*   `requirements.txt`: Lists Python dependencies.
*   `cve_analyzer.py`: Main Python script for command-line execution.
*   `invoke_llm.py`: Contains the function to interact with the Gemini API.
*   `prompt.py`: Defines the system prompt and user prompt structure for the LLM.