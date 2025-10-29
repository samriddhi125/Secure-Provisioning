import json
import requests
from typing import Dict, Any
from pydantic import ValidationError
from intent_models import StreamingIntents
import argparse

class FewShotIntentExtractor:
    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.ollama_url = ollama_url
        self.model = "llama3.2"
    
    def check_ollama_connection(self) -> bool:
        """Check if Ollama is running and the model is available."""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            response.raise_for_status()
            
            models = response.json().get("models", [])
            model_names = [m["name"] for m in models]
            
            print(f"✓ Ollama is running at {self.ollama_url}")
            print(f"✓ Available models: {', '.join(model_names)}")
            
            if any(self.model in name for name in model_names):
                print(f"✓ Model '{self.model}' is available")
                return True
            else:
                print(f"✗ Model '{self.model}' not found")
                print(f"  Run: ollama pull {self.model}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"✗ Cannot connect to Ollama at {self.ollama_url}")
            print(f"  Error: {e}")
            print(f"  Make sure Ollama is running: ollama serve")
            return False
    
    def create_prompt(self, user_request: str) -> str:
        """Create a few-shot prompt with multiple examples."""
        prompt = f"""You are an expert at extracting streaming service requirements from natural language.

Given the user request, extract relevant streaming parameters and movie details. Only include parameters that are explicitly mentioned or strongly implied.

Here are some examples:

Example 1:
Input: "I want to watch Inception in 4K with low latency"
Output:
{{
  "movie_details": {{
    "movie_name": "Inception",
    "language": ""
  }},
  "video_quality": {{
    "resolution": "2160p",
    "frame_rate": null
  }},
  "network_requirements": {{
    "max_latency": "50ms",
    "adaptive_streaming": true
  }},
  "audio_quality": {{
    "codec": null
  }},
  "reliability": {{
    "buffer_strategy": null
  }}
}}

Example 2:
Input: "Stream The Matrix in Hindi with stable connection"
Output:
{{
  "movie_details": {{
    "movie_name": "The Matrix",
    "language": "Hindi"
  }},
  "video_quality": {{
    "resolution": "2160p",
    "frame_rate": null
  }},
  "network_requirements": {{
    "max_latency": "50ms",
    "adaptive_streaming": true
  }},
  "audio_quality": {{
    "codec": null
  }},
  "reliability": {{
    "buffer_strategy": "aggressive"
  }}
}}

Example 3:
Input: "Play Interstellar in HD with smooth playback"
Output:
{{
  "movie_details": {{
    "movie_name": "Interstellar",
    "language": ""
  }},
  "video_quality": {{
    "resolution": "1080p",
    "frame_rate": "60fps"
  }},
  "network_requirements": {{
    "max_latency": "50ms",
    "adaptive_streaming": true
  }},
  "audio_quality": {{
    "codec": null
  }},
  "reliability": {{
    "buffer_strategy": null
  }}
}}

Example 4:
Input: "Watch Dune with AAC audio codec"
Output:
{{
  "movie_details": {{
    "movie_name": "Dune",
    "language": ""
  }},
  "video_quality": {{
    "resolution": "2160p",
    "frame_rate": null
  }},
  "network_requirements": {{
    "max_latency": "50ms",
    "adaptive_streaming": true
  }},
  "audio_quality": {{
    "codec": "AAC"
  }},
  "reliability": {{
    "buffer_strategy": null
  }}
}}

Now extract intents from this request:

User Request: "{user_request}"

Return ONLY a valid JSON object with this exact structure:
{{
  "movie_details": {{
    "movie_name": "string (movie name or empty string)",
    "language": "string (language or empty string)"
  }},
  "video_quality": {{
    "resolution": "string (2160p/1440p/1080p/720p/480p, default: 2160p)",
    "frame_rate": null or "string (60fps/30fps/24fps/120fps)"
  }},
  "network_requirements": {{
    "max_latency": "string (e.g., 50ms, default: 50ms)",
    "adaptive_streaming": true or false (default: true)
  }},
  "audio_quality": {{
    "codec": null or "string (AAC/MP3/FLAC/Opus/AC3/DTS)"
  }},
  "reliability": {{
    "buffer_strategy": null or "string (aggressive/balanced/conservative)"
  }}
}}

Guidelines:
- "4K" or "UHD" = 2160p, "HD" = 1080p, "SD" = 720p
- "low latency" or "fast" = 50ms or less
- "reliable" or "stable" = aggressive buffer_strategy
- "smooth" or "high fps" = 60fps
- Use null for codec and buffer_strategy unless explicitly mentioned
- Use default values: resolution=2160p, max_latency=50ms, adaptive_streaming=true

Return ONLY the JSON object, no explanations."""
        
        return prompt
    
    def call_ollama(self, prompt: str) -> str:
        """Call Ollama API to generate response."""
        try:
            # Try the chat endpoint first
            response = requests.post(
                f"{self.ollama_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "stream": False,
                    "format": "json"
                },
                timeout=60
            )
            
            if response.status_code == 404:
                # Fall back to generate endpoint
                response = requests.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    },
                    timeout=60
                )
            
            response.raise_for_status()
            result = response.json()
            
            if "message" in result:
                return result["message"]["content"]
            elif "response" in result:
                return result["response"]
            else:
                raise ValueError(f"Unexpected response format: {result}")
                
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error calling Ollama: {e}")
    
    def parse_llm_response(self, response: str) -> StreamingIntents:
        """Parse and validate the LLM response using Pydantic."""
        try:
            # Try to parse the response as JSON
            data = json.loads(response)
        except json.JSONDecodeError:
            # Try to find JSON in the response
            start = response.find('{')
            end = response.rfind('}') + 1
            if start != -1 and end > start:
                try:
                    data = json.loads(response[start:end])
                except json.JSONDecodeError:
                    raise ValueError("Could not parse valid JSON from LLM response")
            else:
                raise ValueError("No JSON found in LLM response")
        
        try:
            # Validate and parse with Pydantic
            intents = StreamingIntents(**data)
            return intents
        except ValidationError as e:
            print(f"Validation error: {e}")
            # Return default intents
            intents = StreamingIntents()
            return intents
    
    def extract_intents(self, user_request: str) -> StreamingIntents:
        """Main method to extract intents from user request using few-shot learning."""
        print(f"\n[FEW-SHOT] Processing request: {user_request}")
        
        # Create prompt
        prompt = self.create_prompt(user_request)
        
        # Get LLM response
        print("Calling Ollama...")
        llm_response = self.call_ollama(prompt)
        print(f"LLM Response: {llm_response[:200]}...")
        
        # Parse response with Pydantic
        intents = self.parse_llm_response(llm_response)
        
        return intents
    
    def save_intents(self, intents: StreamingIntents, filename: str = "intents.json"):
        """Save intents to JSON file."""
        with open(filename, 'w') as f:
            f.write(intents.to_json(exclude_none=False))
        print(f"✓ Intents saved to {filename}")

    def predict(self, query):
        try:
            intents = self.extract_intents(query)
            
            print(f"\nExtracted Intents JSON:")
            print(intents.to_json(exclude_none=False))
            return intents.to_json(exclude_none=False)
            # Save to file
            # self.save_intents(intents, f"few_shot_example_{i}.json")
            
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()


def main():
    # Initialize extractor
    extractor = FewShotIntentExtractor()
    
    # Check connection first
    print("="*60)
    print("FEW-SHOT INTENT EXTRACTION")
    print("="*60)
    print("\nChecking Ollama connection...")
    if not extractor.check_ollama_connection():
        print("\nPlease start Ollama and ensure the model is pulled.")
        return
    print("="*60)
    
    # Example requests
    test_requests = [
        "I want to watch Inception in 4K with surround sound",
        "Stream The Matrix in Hindi with low latency",
        "Play Interstellar, keep it stable and reliable",
        "Give me Dune with the best quality possible",
        "Watch Oppenheimer in English with FLAC audio"
    ]
    
    for i, request in enumerate(test_requests, 1):
        print(f"\n{'='*60}")
        print(f"Example {i}")
        print(f"{'='*60}")
        
        try:
            intents = extractor.extract_intents(request)
            
            print(f"\nExtracted Intents JSON:")
            print(intents.to_json(exclude_none=False))
            
            # Save to file
            extractor.save_intents(intents, f"few_shot_example_{i}.json")
            
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    # main()
    fewShot = FewShotIntentExtractor()
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", default="")
    args = parser.parse_args()

    if args.query:
        fewShot.predict(args.query)