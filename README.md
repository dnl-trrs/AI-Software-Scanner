# 🛡️ AI Software Security Scanner

> **AI-Based Software Code Security Analysis & Recommendation Tool**

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/dnl-trrs/AI-Software-Scanner)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![VS Code](https://img.shields.io/badge/VS%20Code-1.74%2B-purple.svg)](https://code.visualstudio.com/)

## 🚀 The Problem We Solve

Developers face increasing cybersecurity threats with new vulnerabilities discovered daily. Data breaches and exploits can cost organizations millions in losses, regulatory fines, and reputational damage. 

**Our Solution:** An AI-powered VS Code extension that not only detects vulnerabilities but also provides:
- ✨ **Automated fix suggestions** with actual code
- 📚 **Educational content** to help developers learn
- 🎯 **Actionable recommendations** that developers can immediately apply
- ⚡ **One-click fixes** integrated into your workflow

## 🏆 What Makes Us Different

| Feature | Our Scanner | Snyk AI | Zerothreat | Qwiet AI |
|---------|------------|---------|------------|----------|
| Vulnerability Detection | ✅ | ✅ | ✅ | ✅ |
| Automated Fix Code | ✅ | ❌ | ❌ | ❌ |
| Educational Content | ✅ | Limited | ❌ | ❌ |
| Best Practices Guide | ✅ | ❌ | ❌ | Limited |
| Time-to-Fix Estimates | ✅ | ❌ | ❌ | ❌ |
| Learning Resources | ✅ | ❌ | ❌ | ❌ |

**Key Differentiator:** We bridge the gap between identifying problems and empowering developers with actionable solutions, making our tool both preventative and educational.

## ✨ Features

### 🔍 Advanced Vulnerability Detection
- **10+ vulnerability types** including:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Path Traversal
  - Command Injection
  - Hardcoded Secrets
  - Weak Cryptography
  - And more!

### 🤖 AI-Powered Recommendations
- **Automatic fix generation** with ready-to-use code
- **Confidence scoring** for each recommendation
- **Multiple solution alternatives**
- **Time estimates** for implementing fixes

### 📚 Educational Integration
- **OWASP guidelines** embedded in recommendations
- **Security best practices** for each vulnerability type
- **Learning resources** (articles, videos, documentation)
- **Interactive tutorials** for secure coding

### 🎨 Beautiful Security Panel
- **Visual dashboard** with vulnerability statistics
- **One-click fix application**
- **Progress tracking** for remediation
- **Export reports** for compliance

## 📦 Installation

### From VS Code Marketplace
1. Open VS Code
2. Press `Ctrl+P` / `Cmd+P`
3. Type `ext install dnl-trrs.ai-software-scanner`
4. Press Enter

### From Source
```bash
# Clone the repository
git clone https://github.com/dnl-trrs/AI-Software-Scanner.git
cd AI-Software-Scanner

# Install dependencies
npm install

# Compile the extension
npm run compile

# Open in VS Code
code .

# Press F5 to run the extension in a new VS Code window
```

## 🎮 Usage

### Quick Start
1. Open any JavaScript, TypeScript, Python, Java, Go, Ruby, PHP, C#, or C/C++ file
2. Press `Shift+Alt+S` (Windows/Linux) or `Shift+Cmd+S` (Mac) to scan
3. View results in the Problems panel or Security Dashboard
4. Click on any vulnerability for fix suggestions
5. Apply fixes with one click!

### Commands

| Command | Description | Shortcut |
|---------|-------------|----------|
| `AI Security: Scan Current File` | Scan the active file for vulnerabilities | `Shift+Alt+S` |
| `AI Security: Scan Workspace` | Scan all files in workspace | - |
| `AI Security: Show Security Panel` | Open the security dashboard | `Shift+Alt+P` |
| `AI Security: Apply Fix` | Apply suggested fix | Click in panel |
| `AI Security: Show Education` | View learning resources | Click in panel |

### Configuration

Customize the scanner in VS Code settings:

```json
{
  "aiSecurityScanner.enable": true,
  "aiSecurityScanner.scanOnSave": true,
  "aiSecurityScanner.scanOnOpen": false,
  "aiSecurityScanner.severityLevel": "medium",
  "aiSecurityScanner.enableEducationalContent": true,
  "aiSecurityScanner.enableAutomaticFixes": true,
  "aiSecurityScanner.aiProvider": "local"
}
```

## 🧪 Example

### Before (Vulnerable Code)
```javascript
// SQL Injection vulnerability
function getUserData(req, res) {
    const userId = req.params.id;
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    connection.query(query, callback);
}
```

### After (AI-Fixed Code)
```javascript
// Secure parameterized query
function getUserData(req, res) {
    const userId = req.params.id;
    const query = "SELECT * FROM users WHERE id = ?";
    connection.query(query, [userId], callback);
}
```

### Educational Content Provided
- **What is SQL Injection?** Explanation of the vulnerability
- **Impact:** Data breach, unauthorized access
- **Best Practices:** Always use parameterized queries
- **Learning Resources:** OWASP SQL Injection Prevention Cheat Sheet
- **Estimated Fix Time:** 30 minutes

## 📊 Supported Languages

- JavaScript / TypeScript
- Python
- Java
- Go
- Ruby
- PHP
- C# / .NET
- C / C++

## 🔒 Security Vulnerabilities Detected

| Vulnerability Type | Severity | Auto-Fix | Education |
|-------------------|----------|----------|------------|
| SQL Injection | Critical | ✅ | ✅ |
| Cross-Site Scripting (XSS) | High | ✅ | ✅ |
| Path Traversal | Critical | ✅ | ✅ |
| Command Injection | Critical | ✅ | ✅ |
| Hardcoded Secrets | Medium | ✅ | ✅ |
| Weak Cryptography | Medium | ✅ | ✅ |
| Insecure Random | Medium | ✅ | ✅ |
| XML External Entity (XXE) | High | ✅ | ✅ |
| Insecure Deserialization | High | ✅ | ✅ |
| Sensitive Data Exposure | Medium | ✅ | ✅ |

## 🤝 Target Users

### Primary Users
- **Software Developers** seeking to write secure code
- **DevOps Engineers** implementing security in CI/CD
- **Security Teams** performing code reviews

### Organizations
- **Tech Startups** building secure products from day one
- **Mid-range Companies** strengthening application security
- **Enterprises** ensuring compliance and security standards

## 🏗️ Architecture

```
┌─────────────────┐
│   VS Code UI    │
│  (Extension)    │
└────────┬────────┘
         │
┌────────▼────────┐
│ Security Scanner│
│    Engine       │
└────────┬────────┘
         │
┌────────▼────────┐
│ AI Recommendation│
│    Engine       │
└────────┬────────┘
         │
┌────────▼────────┐
│  Fix Generator  │
│  & Educator     │
└─────────────────┘
```

## 🛠️ Development

### Prerequisites
- Node.js 16+
- VS Code 1.74+
- TypeScript 5.0+

### Building from Source
```bash
# Install dependencies
npm install

# Run tests
npm test

# Package extension
vsce package

# Publish to marketplace
vsce publish
```

### Testing
```bash
# Run the test file to see detection in action
node test-vulnerable.js

# Or open test-vulnerable.js in VS Code and run the scanner
```

## 📈 Roadmap

- [x] Core vulnerability detection
- [x] AI-powered fix suggestions
- [x] Educational content integration
- [x] VS Code extension UI
- [ ] GitHub/GitLab integration
- [ ] CI/CD pipeline integration
- [ ] Cloud-based scanning API
- [ ] Team collaboration features
- [ ] Custom rule creation
- [ ] Enterprise reporting dashboard

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OWASP for security guidelines
- VS Code team for the excellent extension API
- The open-source security community

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/dnl-trrs/AI-Software-Scanner/issues)
- **Discussions:** [GitHub Discussions](https://github.com/dnl-trrs/AI-Software-Scanner/discussions)
- **Email:** dnl.trrs@example.com

---

<p align="center">
  <strong>🛡️ Secure your code. Educate your team. Build with confidence. 🛡️</strong>
</p>

<p align="center">
  Made with ❤️ by the AI Software Scanner Team
</p>
