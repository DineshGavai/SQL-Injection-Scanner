# 🛡️ SQL Injection Scanner

A modern, web-based SQL injection vulnerability scanner built with FastAPI and featuring a sleek, responsive interface. This tool helps security professionals identify potential SQL injection vulnerabilities in web applications.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-green)
![Status](https://img.shields.io/badge/status-active-success)

## 🌐 Live Demo

Check out the live version of the SQL Injection Scanner:

## 🔗 [SQL Injection Scanner](https://sql-injection-scanner-acqivhuax-dinesh-gavai.vercel.app/)

## ✨ Features

- 🎯 **Automated SQL Injection Detection** - Scans web forms for common SQL injection vulnerabilities
- 🌐 **Modern Web Interface** - Beautiful, responsive design with real-time results
- ⚡ **Fast & Efficient** - Built with FastAPI for high performance
- 🔍 **Multiple Payload Testing** - Tests various SQL injection attack vectors
- 📊 **Detailed Reports** - Comprehensive vulnerability reports with indicators
- 🛡️ **Safe Testing** - Non-destructive scanning methods
- 📱 **Mobile Friendly** - Works perfectly on all devices

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

### Installation

1. **Clone or download the project**

   ```bash
   git clone <https://github.com/DineshGavai/SQL-Injection-Scanner.git>
   cd sql-injection-scanner
   ```

2. **Create a virtual environment** (recommended)

   ```bash
   python -m venv venv

   # On Windows
   venv\Scripts\activate

   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**

   ```bash
   python main.py
   ```

5. **Open your browser**

   Navigate to: `http://localhost:8000`

## 🎮 How to Use

1. **Enter Target URL** - Input the URL of the web application you want to test
2. **Click "Start Security Scan"** - The scanner will automatically find and test all forms
3. **View Results** - Get detailed vulnerability reports with:
   - Number of forms found
   - Detected vulnerabilities
   - Successful payloads
   - Response indicators

### Example URLs to Test

- `https://httpbin.org/forms/post` - Safe testing environment
- Your own development applications
- Authorized penetration testing targets

## 🏗️ Project Structure

```
sql-injection-scanner/
├── main.py              # Main FastAPI application
├── requirements.txt     # Python dependencies
├── static/              # Frontend assets (if using main.py)
│   └── index.html      # Web interface
└── README.md           # This file
```

## 🔧 Configuration

### Scanner Settings

The scanner can be customized by modifying the `SQLInjectionScanner` class in `main.py`:

```python
# Modify payloads
payloads = [
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    "admin'--",
    # Add your custom payloads here
]

# Adjust timeout
response = self.session.get(url, timeout=10)  # Change timeout value
```

### Server Configuration

```python
# Change host and port
uvicorn.run(app, host="127.0.0.1", port=8000)
```

## 🛠️ API Endpoints

| Endpoint  | Method | Description                  |
| --------- | ------ | ---------------------------- |
| `/`       | GET    | Web interface                |
| `/scan`   | POST   | Scan URL for vulnerabilities |
| `/health` | GET    | Health check                 |
| `/docs`   | GET    | API documentation            |

### API Usage Example

```bash
curl -X POST "http://localhost:8000/scan" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com/login"}'
```

## 🧪 Testing Payloads

The scanner tests multiple SQL injection vectors:

- **Boolean-based**: `' OR '1'='1`
- **Union-based**: `" OR "1"="1`
- **Comment-based**: `' OR 1=1--`
- **Authentication bypass**: `admin'--`

## 🚨 Security & Legal Notice

⚠️ **IMPORTANT**: This tool is for educational and authorized security testing purposes only.

- ✅ **DO**: Use on your own applications
- ✅ **DO**: Use with explicit written permission
- ✅ **DO**: Use in authorized penetration testing
- ❌ **DON'T**: Use on applications without permission
- ❌ **DON'T**: Use for malicious purposes

**You are responsible for complying with all applicable laws and regulations.**

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**
4. **Commit your changes**: `git commit -m 'Add amazing feature'`
5. **Push to the branch**: `git push origin feature/amazing-feature`
6. **Open a Pull Request**

### Ideas for Contributions

- 🔍 Additional payload types
- 📊 Export functionality (PDF, JSON reports)
- 🔐 Authentication system
- 📈 Database logging
- 🎨 UI improvements
- 🧪 Unit tests

## 📝 Dependencies

| Package        | Version | Purpose         |
| -------------- | ------- | --------------- |
| FastAPI        | 0.104.1 | Web framework   |
| Uvicorn        | 0.24.0  | ASGI server     |
| Requests       | 2.31.0  | HTTP client     |
| BeautifulSoup4 | 4.12.2  | HTML parsing    |
| Pydantic       | 2.5.0   | Data validation |

## 🐛 Troubleshooting

### Common Issues

**1. Port already in use**

```bash
# Change port in main.py or use:
uvicorn main:app --port 8001
```

**2. Module not found errors**

```bash
pip install -r requirements.txt
```

**3. Permission denied errors**

```bash
# Make sure you have proper permissions and run as administrator if needed
```

**4. Browser can't reach the server**

- Try `http://127.0.0.1:8000` instead of `http://0.0.0.0:8000`
- Check if your firewall is blocking the connection

## 🎯 Roadmap

- [ ] Advanced payload generation
- [ ] Custom header injection testing
- [ ] Blind SQL injection detection
- [ ] Multi-threaded scanning
- [ ] Report export (PDF/HTML)
- [ ] User authentication
- [ ] Scan history and logging
- [ ] Docker containerization

## 👨‍💻 Author

**Dinesh Gavai**

- GitHub: [@yourusername](https://github.com/DineshGavai)
- LinkedIn: [Your LinkedIn](https://linkedin.com/in/dinesh-gavai)
- Email: gavaidinesh26@gmail.com

---

<div align="center">

**⭐ Star this repository if it helped you! ⭐**

Made with ❤️

</div>
