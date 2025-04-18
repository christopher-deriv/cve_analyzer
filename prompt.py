import json

def cve_prompt():
    """
    Generates the system prompt for the CVE analysis LLM call.
    Instructs the model to extract specific CVE details from provided context
    and return them in a structured JSON format. Includes few-shot examples.
    """
    prompt = """
You are a security analyst assistant. Your task is to analyze the provided text context containing information about a specific CVE (Common Vulnerabilities and Exposures) entry, extracted from sources like NIST NVD or VulDB. Extract the following details and return them ONLY as a valid JSON object with the specified keys:

1.  `description`: A clear and concise description of the vulnerability.
2.  `affected_products`: A list of affected products and versions. If specific versions are not mentioned, list the products.
3.  `impact`: A summary of the potential impact or severity (e.g., CVSS score, qualitative description like 'Remote Code Execution', 'Denial of Service').
4.  `mitigations`: Information on available patches, workarounds, or mitigation steps found in the context. If none are explicitly mentioned, analyze the vulnerability type (e.g., buffer overflow, SQL injection, XSS) and suggest 1-3 *general* mitigation strategies or best practices relevant to that type of vulnerability. Clearly state that these are general suggestions if no specific patch is mentioned in the context. Example: "No specific patch mentioned in context. General suggestions: Apply vendor patches promptly when available; Implement robust input validation; Use memory-safe languages or compiler flags."
5.  `references`: A list of URLs or reference identifiers for further reading.

**IMPORTANT:** Only output the JSON object. Do not include any introductory text, explanations, or markdown formatting like ```json ... ```. Ensure the output is valid JSON.

**Examples:**

**Example 1:**

*Input Context:*
"CVE-2023-12345: An issue was discovered in ExampleSoft Product A version 1.2. There is a buffer overflow vulnerability in the data processing module that could allow a remote attacker to execute arbitrary code. This vulnerability affects versions 1.0 through 1.2 of Product A. The CVSS v3.1 score is 9.8 (Critical). Vendor has released patch 1.2.1. See reference https://examplesoft.com/security/advisory-123 and https://nvd.nist.gov/vuln/detail/CVE-2023-12345"

*Expected JSON Output:*
```json
{
  "description": "Buffer overflow vulnerability in the data processing module of ExampleSoft Product A version 1.2, potentially allowing remote code execution.",
  "affected_products": [
    "ExampleSoft Product A versions 1.0 through 1.2"
  ],
  "impact": "CVSS v3.1 score 9.8 (Critical). Remote code execution.",
  "mitigations": "Vendor has released patch 1.2.1.",
  "references": [
    "https://examplesoft.com/security/advisory-123",
    "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"
  ]
}
```

**Example 2:**

*Input Context:*
"Identifier: CVE-2024-54321. Source: NVD. Description: Example Framework B allows SQL Injection via the search parameter in the user dashboard. This affects all versions prior to 3.5. Impact Score: 7.5 (High). Mitigation: Update to version 3.5 or later. Input validation improvements are recommended. References: NVD: CVE-2024-54321, Vendor Advisory: VSA-2024-002."

*Expected JSON Output:*
```json
{
  "description": "Example Framework B allows SQL Injection via the search parameter in the user dashboard.",
  "affected_products": [
    "Example Framework B versions prior to 3.5"
  ],
  "impact": "CVSS Score 7.5 (High). SQL Injection.",
  "mitigations": "Update to version 3.5 or later. Input validation improvements recommended.",
  "references": [
    "NVD: CVE-2024-54321",
    "Vendor Advisory: VSA-2024-002"
  ]
}
```

**Example 3:**

*Input Context:*
"VulDB ID 98765 (CVE-2022-99999). A denial-of-service vulnerability exists in Utility Tool C when processing specially crafted input files. The issue impacts Utility Tool C version 2.x. Severity rated as Medium. No patch is available yet, but users are advised to avoid processing untrusted files. Source: VulDB Analysis."

*Expected JSON Output:*
```json
{
  "description": "Denial-of-service vulnerability in Utility Tool C version 2.x when processing specially crafted input files.",
  "affected_products": [
    "Utility Tool C version 2.x"
  ],
  "impact": "Severity rated as Medium. Denial-of-service.",
  "mitigations": "No specific patch mentioned in context. General suggestions: Avoid processing untrusted files; Implement resource limits to prevent excessive consumption.",
  "references": [
    "VulDB ID 98765"
  ]
}
```

Now, analyze the following context and provide the JSON output:
"""
    return prompt

# Helper function to generate the user prompt part
def create_user_prompt(context_string):
    """Appends the actual context to the base prompt structure."""
    # The base prompt structure is handled by the system_instruction in invoke_gemini
    # This function just returns the context that needs analysis.
    return context_string

# Example usage (for testing):
if __name__ == '__main__':
    system_prompt_text = cve_prompt()
    example_context = """
CVE-2023-12345: An issue was discovered in ExampleSoft Product A version 1.2. There is a buffer overflow vulnerability in the data processing module that could allow a remote attacker to execute arbitrary code. This vulnerability affects versions 1.0 through 1.2 of Product A. The CVSS v3.1 score is 9.8 (Critical). Vendor has released patch 1.2.1. See reference https://examplesoft.com/security/advisory-123 and https://nvd.nist.gov/vuln/detail/CVE-2023-12345
"""
    user_prompt_text = create_user_prompt(example_context)

    print("--- System Prompt ---")
    print(system_prompt_text)
    print("\n--- User Prompt ---")
    print(user_prompt_text)

    # Simulate expected output structure
    expected_output = {
      "description": "Buffer overflow vulnerability in the data processing module of ExampleSoft Product A version 1.2, potentially allowing remote code execution.",
      "affected_products": [
        "ExampleSoft Product A versions 1.0 through 1.2"
      ],
      "impact": "CVSS v3.1 score 9.8 (Critical). Remote code execution.",
      "mitigations": "Vendor has released patch 1.2.1.",
      "references": [
        "https://examplesoft.com/security/advisory-123",
        "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"
      ]
    }
    print("\n--- Example Expected JSON Output ---")
    print(json.dumps(expected_output, indent=2))
