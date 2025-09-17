#!/usr/bin/env python3
"""
Setup script for CyberForensics Pro AI Edition
Helps configure API keys and install dependencies
"""

import os
import subprocess
import sys

def install_requirements():
    """Install required packages"""
    print("🔧 Installing AI dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements_ai.txt"])
        print("✅ Dependencies installed successfully!")
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        return False
    return True

def setup_api_keys():
    """Help user set up API keys"""
    print("\n🔑 API Key Setup")
    print("=" * 50)
    
    # OpenAI API Key
    openai_key = input("Enter your OpenAI API key (or press Enter to skip): ").strip()
    if openai_key:
        os.environ['OPENAI_API_KEY'] = openai_key
        print("✅ OpenAI API key configured")
    else:
        print("⚠️  OpenAI API key skipped - AI features will use heuristics only")
    
    # VirusTotal API Key
    vt_key = input("Enter your VirusTotal API key (or press Enter to skip): ").strip()
    if vt_key:
        os.environ['VIRUSTOTAL_API_KEY'] = vt_key
        print("✅ VirusTotal API key configured")
    else:
        print("⚠️  VirusTotal API key skipped - IP reputation will use basic checks")
    
    # Create .env file
    if openai_key or vt_key:
        with open('.env', 'w') as f:
            if openai_key:
                f.write(f"OPENAI_API_KEY={openai_key}\n")
            if vt_key:
                f.write(f"VIRUSTOTAL_API_KEY={vt_key}\n")
        print("✅ .env file created")

def main():
    print("🚀 CyberForensics Pro AI Edition Setup")
    print("=" * 50)
    
    # Install dependencies
    if not install_requirements():
        return
    
    # Setup API keys
    setup_api_keys()
    
    print("\n🎉 Setup Complete!")
    print("\n📋 Next Steps:")
    print("1. Run: python backend.py")
    print("2. Open: winning_app.html in your browser")
    print("3. Test the AI-powered email analysis!")
    
    print("\n💡 Pro Tips:")
    print("- Get OpenAI API key from: https://platform.openai.com/api-keys")
    print("- Get VirusTotal API key from: https://www.virustotal.com/gui/join-us")
    print("- Without API keys, the app uses advanced heuristics (still impressive!)")

if __name__ == "__main__":
    main()