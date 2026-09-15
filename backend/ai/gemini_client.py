import os
import re
import json
from typing import Optional, Dict, Any
from dotenv import load_dotenv
from google import genai

load_dotenv()

class GeminiClient:
    """
    Client for interacting with Google Gemini API models.
    Supports structured JSON generation, automated model fallback, and robust response parsing.
    """

    SUPPORTED_MODELS = [
        "gemini-2.5-flash",
        "gemini-3.6-flash",
        "gemini-3.5-flash",
        "gemini-flash-latest",
        "gemini-2.5-pro"
    ]

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            # Fallback check directly in .env file
            env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
            if os.path.exists(env_path):
                load_dotenv(env_path)
                self.api_key = os.getenv("GEMINI_API_KEY")

        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not set. Please provide it in backend/.env")

        self.client = genai.Client(api_key=self.api_key)
        self.active_model = self.SUPPORTED_MODELS[0]

    def generate_json_response(self, prompt: str, system_instruction: Optional[str] = None) -> Dict[str, Any]:
        """
        Sends prompt to Gemini and parses the response strictly as a JSON dictionary.
        Includes automatic retry for transient 500/503 network and server errors.
        """
        import time
        last_exception = None

        for model_name in self.SUPPORTED_MODELS:
            for attempt in range(1, 4):
                try:
                    from google.genai import types
                    
                    config = types.GenerateContentConfig(
                        system_instruction=system_instruction if system_instruction else None,
                        response_mime_type="application/json",
                        temperature=0.1
                    )

                    response = self.client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config=config
                    )

                    if response and response.text:
                        self.active_model = model_name
                        cleaned_text = self._clean_json_string(response.text)
                        try:
                            return json.loads(cleaned_text, strict=False)
                        except json.JSONDecodeError:
                            # Secondary fallback for escaped quotes or control chars
                            import ast
                            try:
                                return ast.literal_eval(cleaned_text)
                            except Exception:
                                # Re-raise with strict=False error
                                return json.loads(cleaned_text, strict=False)

                except Exception as e:
                    last_exception = e
                time.sleep(1.5 * attempt)
                continue

        # If all models failed, raise the final exception
        raise RuntimeError(f"Gemini API request failed across all models. Last error: {str(last_exception)}")

    def _clean_json_string(self, text: str) -> str:
        """
        Removes any leading/trailing markdown code fences, thought tokens, or commentary
        and extracts the primary JSON object.
        """
        cleaned = text.strip()
        # Find the outermost JSON object bounds
        match = re.search(r"(\{[\s\S]*\})", cleaned)
        if match:
            return match.group(1).strip()
        
        # Fallback stripping
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        return cleaned.strip()

# Global singleton
gemini_client = GeminiClient()
