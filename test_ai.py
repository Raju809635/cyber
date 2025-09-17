#!/usr/bin/env python3
"""
Test script to verify AI functionality
"""
import os
import requests
import json

def test_openai():
    """Test OpenAI API connection"""
    try:
        import openai
        api_key = os.getenv('OPENAI_API_KEY')
        
        if not api_key or api_key == 'your-openai-api-key-here':
            print("❌ OpenAI API key not found")
            return False
            
        openai.api_key = api_key
        
        # Test API call
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "Test: Is this a phishing email? 'URGENT: Click here to verify your account'"}],
            max_tokens=50
        )
        
        print("✅ OpenAI API working!")
        print(f"Response: {response.choices[0].message.content}")
        return True
        
    except Exception as e:
        print(f"❌ OpenAI API error: {e}")
        return False

def test_backend_ai():
    """Test backend AI endpoint"""
    try:
        # Test AI analysis endpoint
        test_email = "URGENT: Your account will be suspended! Click here immediately to verify: http://fake-bank.com/verify"
        
        response = requests.post('http://127.0.0.1:5000/api/ai-analysis', 
                               json={'content': test_email, 'type': 'full'},
                               timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Backend AI endpoint working!")
            print(f"Threat Score: {result.get('threat_score')}")
            print(f"AI Powered: {result.get('ai_powered')}")
            print(f"Indicators: {result.get('indicators')}")
            return True
        else:
            print(f"❌ Backend error: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Backend not running. Start with: python backend.py")
        return False
    except Exception as e:
        print(f"❌ Backend test error: {e}")
        return False

def test_email_analysis():
    """Test email analysis endpoint"""
    try:
        test_data = {
            'headers': 'From: suspicious@fake-bank.com\nTo: victim@company.com\nSubject: URGENT ACTION REQUIRED',
            'senderIP': '185.220.101.42',
            'domain': 'fake-bank.com'
        }
        
        response = requests.post('http://127.0.0.1:5000/api/analyze-email', 
                               json=test_data, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Email analysis working!")
            print(f"Threat Level: {result.get('threat_level')}")
            print(f"Threat Score: {result.get('threat_score')}")
            print(f"Country: {result.get('origin_country')}")
            return True
        else:
            print(f"❌ Email analysis error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Email analysis test error: {e}")
        return False

def main():
    print("🧪 Testing AI Functionality")
    print("=" * 40)
    
    # Load environment variables
    if os.path.exists('.env'):
        with open('.env', 'r') as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value
        print("✅ Environment variables loaded")
    else:
        print("⚠️  No .env file found")
    
    print("\n1. Testing OpenAI API...")
    openai_works = test_openai()
    
    print("\n2. Testing Backend AI...")
    backend_works = test_backend_ai()
    
    print("\n3. Testing Email Analysis...")
    email_works = test_email_analysis()
    
    print("\n" + "=" * 40)
    print("📊 Test Results:")
    print(f"OpenAI API: {'✅ Working' if openai_works else '❌ Failed'}")
    print(f"Backend AI: {'✅ Working' if backend_works else '❌ Failed'}")
    print(f"Email Analysis: {'✅ Working' if email_works else '❌ Failed'}")
    
    if all([backend_works, email_works]):
        print("\n🎉 AI System is working! Your app is hackathon-ready!")
        if openai_works:
            print("🚀 Full AI power with OpenAI integration!")
        else:
            print("🧠 Running on advanced heuristics (still impressive!)")
    else:
        print("\n⚠️  Some issues detected. Check backend is running.")

if __name__ == "__main__":
    main()