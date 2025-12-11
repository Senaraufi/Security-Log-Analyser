# Security API - Web Interface for Log Analysis

A Rust-based web API that provides a beautiful frontend for analyzing security logs.

## 🚀 Features

- **File Upload** - Drag and drop or select log files
- **Real-time Analysis** - Instant threat detection
- **Beautiful UI** - Modern, responsive design
- **JSON API** - RESTful endpoints for programmatic access
- **Fast** - Rust-powered performance

## 🛠️ Tech Stack

- **Backend:** Axum (Rust web framework)
- **Frontend:** Vanilla HTML/CSS/JavaScript
- **Parsing:** Regex-based log analysis
- **Async:** Tokio runtime

## 📦 Installation

```bash
cd security_api
cargo build --release
```

## 🎯 Usage

### Start the Server

```bash
cargo run
```

The server will start on `http://localhost:3000`

### Using the Web Interface

1. Open `http://localhost:3000` in your browser
2. Click "Choose Log File" and select a `.txt` or `.log` file
3. Click "Analyze Logs"
4. View the results:
   - Threat statistics
   - IP address analysis
   - Risk assessment

### Using the API Programmatically

```bash
# Upload and analyze logs
curl -X POST http://localhost:3000/api/analyze \
  -F "file=@sample_logs.txt"
```

**Response:**
```json
{
  "threat_statistics": {
    "failed_logins": 10,
    "root_attempts": 5,
    "suspicious_file_access": 1,
    "critical_alerts": 4
  },
  "ip_analysis": {
    "high_risk_ips": [
      {
        "ip": "192.168.1.100",
        "count": 11,
        "risk_level": "high"
      }
    ],
    "all_ips": [...]
  },
  "risk_assessment": {
    "level": "HIGH",
    "total_threats": 20,
    "description": "Immediate action required"
  }
}
```

## 🔍 Detection Rules

The API detects 4 types of security threats:

1. **Failed Login Attempts** - ERROR level + "Failed login" in message
2. **Root User Access** - Any log containing "user: root"
3. **Suspicious File Access** - Access to `/etc/passwd`, `/etc/shadow`
4. **Critical Alerts** - CRITICAL severity level

## 📊 Risk Levels

- **HIGH** (🔴) - 10+ threat indicators
- **MEDIUM** (🟡) - 5-9 threat indicators
- **LOW** (🟢) - 0-4 threat indicators

## 🎨 API Endpoints

### `GET /`
Returns the web interface (HTML)

### `POST /api/analyze`
Analyzes uploaded log file

**Request:**
- Content-Type: `multipart/form-data`
- Field: `file` (log file)

**Response:**
- Content-Type: `application/json`
- Body: `AnalysisResult` object

## 🧪 Testing

Test with the sample logs from the `log_parser` project:

```bash
# Copy sample logs
cp ../log_parser/sample_logs.txt .

# Start server
cargo run

# Upload via web interface at http://localhost:3000
```

## 📁 Project Structure

```
security_api/
├── src/
│   └── main.rs          # Axum server + embedded HTML
├── Cargo.toml           # Dependencies
└── README.md            # This file
```

## 🔧 Dependencies

```toml
axum = "0.7"              # Web framework
tokio = "1"               # Async runtime
serde = "1.0"             # JSON serialization
regex = "1.10"            # Log parsing
tower-http = "0.5"        # HTTP utilities
```

## 🚀 Next Steps

- [ ] Add AI integration (OpenAI/Claude)
- [ ] Real-time log streaming
- [ ] Database storage (PostgreSQL)
- [ ] User authentication
- [ ] Export reports (PDF/CSV)
- [ ] Dashboard with charts
- [ ] WebSocket for live updates

## 📝 License

Private project - All rights reserved
