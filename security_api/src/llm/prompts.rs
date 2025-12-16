use crate::parsers::apache::ApacheLog;

/// Prompt builder for security analysis
/// This is competitive advantage - these prompts encode security expertise
pub struct PromptBuilder {
    logs: Vec<ApacheLog>,
    context: String,
}

impl PromptBuilder {
    pub fn new() -> Self {
        Self {
            logs: Vec::new(),
            context: String::new(),
        }
    }
    
    pub fn with_logs(mut self, logs: &[ApacheLog]) -> Self {
        self.logs = logs.to_vec();
        self
    }
    
    pub fn with_context(mut self, context: String) -> Self {
        self.context = context;
        self
    }
    
    /// Build a comprehensive security analysis prompt
    /// This encodes SOC analyst expertise into the prompt
    pub fn build_security_analysis(&self) -> String {
        let log_summary = self.format_logs_for_analysis();
        let suspicious_logs = self.format_suspicious_logs();
        let threat_statistics = self.calculate_threat_stats();
        
        format!(r#"You are a senior Security Operations Center (SOC) analyst with 10+ years of experience in threat detection, incident response, and security log analysis. You specialize in web application security, network forensics, and threat intelligence.

## Your Task
Analyze the following Apache web server logs for security threats, attack patterns, and anomalies. Provide a comprehensive security assessment with actionable recommendations.

## Log Statistics
- Total logs analyzed: {}
- Suspicious entries: {}
- Time range: {} to {}

{}

## Suspicious Logs Requiring Analysis
{}

## Analysis Framework
Use the following frameworks and methodologies:

### 1. MITRE ATT&CK Framework
- Initial Access (T1190 - Exploit Public-Facing Application)
- Execution (T1059 - Command and Scripting Interpreter)
- Persistence (T1505 - Server Software Component)
- Discovery (T1046 - Network Service Scanning)
- Collection (T1005 - Data from Local System)
- Exfiltration (T1041 - Exfiltration Over C2 Channel)

### 2. OWASP Top 10 (2021)
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection (SQL, Command, XSS)
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable Components
- A07: Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging Failures
- A10: Server-Side Request Forgery

### 3. Attack Pattern Recognition
Look for:
- **SQL Injection**: UNION SELECT, OR 1=1, quote escaping, comment sequences (--, /*, #)
- **Path Traversal**: ../, ..\, %2e%2e%2f, absolute paths
- **Cross-Site Scripting (XSS)**: <script>, javascript:, onerror=, onload=, eval()
- **Command Injection**: ;, |, &&, ||, backticks, $()
- **Authentication Attacks**: Repeated 401/403, credential stuffing, brute force
- **Scanner Activity**: Nmap, Nikto, SQLMap, Burp, Acunetix, ZAP
- **Data Exfiltration**: Large response sizes, unusual patterns
- **Reconnaissance**: Directory enumeration, file discovery, version detection

### 4. Behavioral Analysis
- **Temporal Patterns**: Burst activity, off-hours access, rapid requests
- **Geographic Anomalies**: Unusual source countries, VPN/proxy usage
- **User-Agent Analysis**: Automated tools, outdated browsers, suspicious patterns
- **HTTP Method Abuse**: Unusual methods, method tampering
- **Status Code Patterns**: 404 scanning, 500 errors (exploitation attempts)

## Required Output Format

Provide your analysis in the following structure:

### Executive Summary
[2-3 sentences summarizing the overall security posture and key findings]

### Threat Level Assessment
Overall Threat Level: [Critical/High/Medium/Low/None]
Confidence: [0-100%]

### Key Findings
For each significant finding:
1. **[Attack Type]** - Severity: [Critical/High/Medium/Low]
   - Description: [What was detected]
   - Evidence: [Specific log entries or patterns]
   - Affected Resources: [IPs, paths, endpoints]
   - MITRE ATT&CK Mapping: [Technique ID and name]
   - Confidence: [0-100%]

### Attack Chain Analysis
Identify related events that form attack chains:
- Chain 1: [Name]
  - Timeline: [Event sequence]
  - Source IPs: [List]
  - Description: [How events are related]
  - Intent: [What attacker was trying to achieve]

### False Positive Assessment
For each potential false positive:
- Pattern: [What triggered alert]
- Reason: [Why it might be legitimate]
- Recommendation: [How to verify]

### Indicators of Compromise (IOCs)
- Malicious IPs: [List with context]
- Suspicious User-Agents: [List]
- Attack Patterns: [Regex or signatures]
- Malicious Paths: [URLs/endpoints]

### Risk Assessment
- Immediate Risks: [What needs urgent attention]
- Potential Impact: [What could happen]
- Exploitability: [How easy to exploit]

### Recommendations
Priority-ordered actions:
1. **Immediate Actions** (0-24 hours)
   - [Specific, actionable steps]
2. **Short-term Actions** (1-7 days)
   - [Specific, actionable steps]
3. **Long-term Improvements** (1-3 months)
   - [Strategic recommendations]

### Detection Rules
Suggest specific detection rules or SIEM queries to catch similar attacks:
```
[Rule format: condition → action]
```

### Additional Context
- Related CVEs (if applicable)
- Threat actor TTPs (if identifiable)
- Similar historical attacks
- Industry-specific considerations

## Important Guidelines
1. **Be Specific**: Reference actual log entries, IPs, timestamps
2. **Reduce False Positives**: Distinguish between legitimate testing and real attacks
3. **Context Matters**: Consider normal application behavior
4. **Prioritize**: Focus on critical and high-severity findings first
5. **Actionable**: Every recommendation should be implementable
6. **Evidence-Based**: Support conclusions with log evidence
7. **Consider Intent**: Differentiate between scanning and active exploitation

Begin your analysis now."#,
            self.logs.len(),
            self.logs.iter().filter(|l| l.is_suspicious).count(),
            self.get_earliest_timestamp(),
            self.get_latest_timestamp(),
            threat_statistics,
            suspicious_logs,
        )
    }
    
    fn format_logs_for_analysis(&self) -> String {
        let mut output = String::new();
        
        for (i, log) in self.logs.iter().enumerate() {
            output.push_str(&format!(
                "{}. {} - {} {} {} - Status: {} - Size: {} - UA: {}\n",
                i + 1,
                log.ip,
                log.method,
                log.path,
                log.protocol,
                log.status,
                log.size,
                log.user_agent
            ));
        }
        
        output
    }
    
    fn format_suspicious_logs(&self) -> String {
        let suspicious: Vec<&ApacheLog> = self.logs.iter()
            .filter(|l| l.is_suspicious)
            .collect();
        
        if suspicious.is_empty() {
            return "No suspicious logs detected by initial analysis.".to_string();
        }
        
        let mut output = String::new();
        
        for (i, log) in suspicious.iter().enumerate() {
            output.push_str(&format!(
                "\n### Suspicious Entry #{}\n",
                i + 1
            ));
            output.push_str(&format!("- **Timestamp**: {}\n", log.timestamp));
            output.push_str(&format!("- **Source IP**: {}\n", log.ip));
            output.push_str(&format!("- **Request**: {} {} {}\n", log.method, log.path, log.protocol));
            output.push_str(&format!("- **Status Code**: {}\n", log.status));
            output.push_str(&format!("- **Response Size**: {} bytes\n", log.size));
            output.push_str(&format!("- **User-Agent**: {}\n", log.user_agent));
            output.push_str(&format!("- **Referer**: {}\n", log.referer));
            
            if let Some(ref threat_type) = log.threat_type {
                output.push_str(&format!("- **Detected Threat**: {}\n", threat_type));
            }
            
            if let Some(ref severity) = log.severity {
                output.push_str(&format!("- **Initial Severity**: {}\n", severity));
            }
            
            output.push('\n');
        }
        
        output
    }
    
    fn calculate_threat_stats(&self) -> String {
        let mut stats = String::from("## Threat Statistics\n");
        
        // Count by threat type
        let mut threat_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        
        for log in &self.logs {
            if let Some(ref threat_type) = log.threat_type {
                *threat_counts.entry(threat_type.clone()).or_insert(0) += 1;
            }
        }
        
        if !threat_counts.is_empty() {
            stats.push_str("### Detected Threat Types:\n");
            for (threat_type, count) in threat_counts.iter() {
                stats.push_str(&format!("- {}: {} occurrence(s)\n", threat_type, count));
            }
        }
        
        // Count by status code
        let mut status_counts: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
        for log in &self.logs {
            *status_counts.entry(log.status).or_insert(0) += 1;
        }
        
        stats.push_str("\n### HTTP Status Code Distribution:\n");
        let mut status_vec: Vec<_> = status_counts.iter().collect();
        status_vec.sort_by_key(|(status, _)| *status);
        
        for (status, count) in status_vec {
            stats.push_str(&format!("- {}: {} requests\n", status, count));
        }
        
        // Count by IP
        let mut ip_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for log in &self.logs {
            *ip_counts.entry(log.ip.clone()).or_insert(0) += 1;
        }
        
        stats.push_str("\n### Top Source IPs:\n");
        let mut ip_vec: Vec<_> = ip_counts.iter().collect();
        ip_vec.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        
        for (ip, count) in ip_vec.iter().take(10) {
            stats.push_str(&format!("- {}: {} requests\n", ip, count));
        }
        
        stats
    }
    
    fn get_earliest_timestamp(&self) -> String {
        self.logs.first()
            .map(|l| l.timestamp.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string())
    }
    
    fn get_latest_timestamp(&self) -> String {
        self.logs.last()
            .map(|l| l.timestamp.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string())
    }
}

impl Default for PromptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    
    #[test]
    fn test_prompt_builder() {
        let mut log = ApacheLog {
            ip: "192.168.1.100".to_string(),
            timestamp: Utc::now(),
            method: "GET".to_string(),
            path: "/admin' OR 1=1--".to_string(),
            protocol: "HTTP/1.1".to_string(),
            status: 500,
            size: 0,
            referer: "-".to_string(),
            user_agent: "sqlmap/1.0".to_string(),
            is_suspicious: true,
            threat_type: Some("SQL Injection".to_string()),
            severity: Some("Critical".to_string()),
        };
        
        let prompt = PromptBuilder::new()
            .with_logs(&vec![log])
            .build_security_analysis();
        
        assert!(prompt.contains("SOC analyst"));
        assert!(prompt.contains("MITRE ATT&CK"));
        assert!(prompt.contains("OWASP"));
        assert!(prompt.contains("SQL Injection"));
    }
}
