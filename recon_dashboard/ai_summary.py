import os
import json
from google import genai
from google.genai import types

def generate_summary(recon_data):
    api_key = os.environ.get("GEMINI_API_KEY")
    prompt = f"""
    You are a cybersecurity blue-team assistant. Analyze the following passive reconnaissance data.
    Provide a professional summary suitable for an academic presentation.
    
    Constraints:
    1. Classify findings strictly as 'Informational' or 'Low Risk'.
    2. Explain why missing security headers or exposed tech stacks matter.
    3. Provide defensive insights to improve the blue-team posture.
    
    Data:
    {json.dumps(recon_data, indent=2, default=str)}
    """

    if api_key:
        try:
            client = genai.Client()
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt,
                config=types.GenerateContentConfig(temperature=0.2)
            )
            return response.text
        except Exception as e:
            return f"AI API Error: {str(e)}\n\nFallback Analysis: Data successfully collected. Review missing headers manually for Low Risk vulnerabilities."
    else:
        # Fallback if no API key is provided
        missing_headers = []
        if "web_analysis" in recon_data and "security_headers" in recon_data["web_analysis"]:
            headers = recon_data["web_analysis"]["security_headers"]
            missing_headers = [k for k, v in headers.items() if v == "Missing"]
            
        return f"""
        **AI Summary (Rule-Based Fallback - No API Key Found)**
        
        **Classification:** Informational / Low Risk
        
        **Analysis:**
        The passive scan successfully mapped the infrastructure for {recon_data.get('domain')}. 
        - **Informational:** WHOIS and DNS records are exposed as expected for public routing.
        - **Low Risk:** The following security headers are missing: {', '.join(missing_headers) if missing_headers else 'None detected'}. 
        
        **Defensive Insights:**
        Consider implementing missing HTTP security headers (like Content-Security-Policy and Strict-Transport-Security) to mitigate client-side attacks (XSS, Clickjacking) and enforce encrypted communications. Ensure robots.txt does not inadvertently expose sensitive administrative directories.
        """
