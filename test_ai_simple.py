import os
import requests

def test_ai():
    print("Testing AI Functionality")
    print("=" * 40)
    
    # Test 1: Check API keys
    openai_key = os.getenv('OPENAI_API_KEY')
    vt_key = os.getenv('VIRUSTOTAL_API_KEY')
    
    print(f"OpenAI Key: {'Found' if openai_key and openai_key != 'your-openai-api-key-here' else 'Missing'}")
    print(f"VirusTotal Key: {'Found' if vt_key and vt_key != 'your-virustotal-api-key-here' else 'Missing'}")
    
    # Test 2: Backend AI endpoint
    try:
        test_email = "URGENT: Click here to verify your account immediately!"
        response = requests.post('http://127.0.0.1:5000/api/ai-analysis', 
                               json={'content': test_email, 'type': 'full'}, timeout=5)
        
        if response.status_code == 200:
            result = response.json()
            print("Backend AI: Working")
            print(f"Threat Score: {result.get('threat_score')}")
            print(f"AI Powered: {result.get('ai_powered')}")
            return True
        else:
            print(f"Backend AI: Error {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("Backend AI: Not running - Start with 'python backend.py'")
        return False
    except Exception as e:
        print(f"Backend AI: Error - {e}")
        return False

if __name__ == "__main__":
    test_ai()