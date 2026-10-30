import requests
import json

def query_gemini(prompt: str, data: dict) -> str | None:
    API_KEY = "ENTER API KEY HERE"
    API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent"

    headers = {
        "x-goog-api-key": API_KEY,
        "Content-Type": "application/json",
    }

    full_prompt = f"{prompt}\n{json.dumps(data, indent=2)}"

    payload = {
        "contents": [{"parts": [{"text": full_prompt}]}],
        "generationConfig": {
            "temperature": 0.7,
            "topP": 0.95,
        },
    }

    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        response.raise_for_status()
        result = response.json()
        return result["candidates"][0]["content"]["parts"][0]["text"]
        
    except requests.exceptions.RequestException as e:
        print(f"Error during API request: {e}")
        if e.response is not None:
            print(e.response.text)  # Google's error body explains the cause
        return None
    except (KeyError, IndexError):
        print(f"Unexpected response shape: {response.text}")
        return None


if __name__ == "__main__":

    #Sample Prompt
    my_prompt = "Write Me A Project Plan With the following details:"

    #Sample Data, consider passing data for tasks in required form?
    sales_data = {"Task Name": "Equipment Refresh", "Volume": "100 devices", "revenue": 5000.00}

    #Method call
    gemini_response = query_gemini(my_prompt, sales_data)

    #print
    if gemini_response:
        print(f"Gemini's Response: {gemini_response}")