# Quick Start Guide

## 🚀 Get Started in 3 Steps

### Step 1: Start the Server

```bash
cd /Users/senaraufi/Desktop/Startup/security_api
cargo run --release
```

You should see:
```
🚀 Security API Server running on http://localhost:3000
📊 Upload logs at: http://localhost:3000
```

### Step 2: Open in Browser

Open your web browser and go to:
```
http://localhost:3000
```

### Step 3: Upload Logs

1. Click "📁 Choose Log File"
2. Select `../log_parser/sample_logs.txt`
3. Click "Analyze Logs"
4. View the results!

## 🎨 What You'll See

The web interface shows:
- **Threat Statistics** - Failed logins, root attempts, file access, critical alerts
- **IP Analysis** - High-risk IPs with 3+ occurrences
- **Risk Assessment** - Overall risk level (HIGH/MEDIUM/LOW)

## 🔧 Troubleshooting

### Port Already in Use?
If port 3000 is busy, the server will fail to start. Kill the process using port 3000:
```bash
lsof -ti:3000 | xargs kill -9
```

### Can't Find Sample Logs?
Copy them to the current directory:
```bash
cp ../log_parser/sample_logs.txt .
```

## 📡 API Usage

Test the API with curl:
```bash
curl -X POST http://localhost:3000/api/analyze \
  -F "file=@../log_parser/sample_logs.txt"
```

## 🎯 Next Steps

- Try uploading your own log files
- Check the JSON response from the API
- Modify the detection rules in `src/main.rs`
- Add more threat patterns

## 🛑 Stop the Server

Press `Ctrl+C` in the terminal where the server is running.

---

**Enjoy your security log analyzer!** 🔒
