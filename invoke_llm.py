import logging
from dotenv import load_dotenv
from google import genai
from google.genai import types
import os

load_dotenv()

logger = logging.getLogger(__name__)
gemini_api_key = os.getenv("GEMINI_API_KEY")

def invoke_gemini(model,system_prompt,user_prompt,token_output,temperature):

    client = genai.Client(api_key=gemini_api_key)

    response = client.models.generate_content(
        model=model,
        config=types.GenerateContentConfig(
            # Sets the maximum number of tokens to include in a candidate.
            max_output_tokens=token_output,
            # Controls the randomness of the output. Use higher values for more creative responses, and lower values for more deterministic responses. Values can range from [0.0, 2.0]
            temperature=temperature,
            system_instruction=system_prompt
            ),
        contents=user_prompt
    )
    # Check if response has text attribute and return it, otherwise return an error JSON string
    try:
        # Access response.text directly as indicated by original code and error
        response_text = response.text
        logger.info("Received text response from Gemini.")
        logger.debug(f"Raw response text: {response_text}")
        return response_text
    except AttributeError:
        # Handle cases where .text might also be missing or response is structured differently
        logger.warning(f"Gemini response does not have .text attribute or is structured unexpectedly. Response: {response}")
        error_payload = {"error": "Empty or unexpected response structure from LLM."}
        # Attempt to check other common attributes for error info if .text fails
        try:
            if response.prompt_feedback and response.prompt_feedback.block_reason:
                 error_payload["details"] = f"Prompt blocked due to: {response.prompt_feedback.block_reason}"
                 logger.error(error_payload["details"])
            elif response.candidates and response.candidates[0].finish_reason != 'STOP':
                 error_payload["details"] = f"Generation stopped due to: {response.candidates[0].finish_reason}"
                 logger.error(error_payload["details"])
        except AttributeError:
             logger.warning("Could not access detailed feedback/candidates attributes either.")

        import json # Ensure json is imported
        return json.dumps(error_payload) # Return error as JSON string
