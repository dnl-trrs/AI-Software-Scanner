/**
 * Core Security Scanner Module
 * Detects vulnerabilities in code and provides actionable recommendations
 */

import * as vscode from 'vscode';

export interface Vulnerability {
    id: string;
    type: VulnerabilityType;
    severity: 'low' | 'medium' | 'high' | 'critical';
    line: number;
    column: number;
    endLine?: number;
    endColumn?: number;
    message: string;
    file: string;
    code: string;
    recommendation?: string;
    educationalContent?: string;
    automaticFix?: string;
}

export enum VulnerabilityType {
    SQL_INJECTION = 'SQL_INJECTION',
    XSS = 'CROSS_SITE_SCRIPTING',
    PATH_TRAVERSAL = 'PATH_TRAVERSAL',
    INSECURE_RANDOM = 'INSECURE_RANDOM',
    HARDCODED_SECRET = 'HARDCODED_SECRET',
    WEAK_CRYPTO = 'WEAK_CRYPTOGRAPHY',
    COMMAND_INJECTION = 'COMMAND_INJECTION',
    XXE = 'XML_EXTERNAL_ENTITY',
    INSECURE_DESERIALIZATION = 'INSECURE_DESERIALIZATION',
    SENSITIVE_DATA_EXPOSURE = 'SENSITIVE_DATA_EXPOSURE'
}

export class SecurityScanner {
    private vulnerabilities: Vulnerability[] = [];
    private patterns: Map<VulnerabilityType, RegExp[]> = new Map();

    constructor() {
        this.initializePatterns();
    }

    /**
     * Initialize vulnerability detection patterns
     * These patterns identify common security issues
     */
    private initializePatterns(): void {
        // SQL Injection patterns
        this.patterns.set(VulnerabilityType.SQL_INJECTION, [
            /query\s*\(\s*['"`].*\+.*\$\{.*\}/gi,
            /query\s*\(\s*['"`].*\+.*\w+.*['"`]\s*\)/gi,
            /execute\s*\(\s*['"`].*\+.*\$\{.*\}/gi,
            /SELECT.*FROM.*WHERE.*['"`]\s*\+/gi,
            /INSERT\s+INTO.*VALUES.*\+.*\$\{/gi
        ]);

        // XSS patterns
        this.patterns.set(VulnerabilityType.XSS, [
            /innerHTML\s*=\s*[^'"`].*\$\{/gi,
            /document\.write\s*\(.*\$\{/gi,
            /\$\{.*\}.*<\/script>/gi,
            /dangerouslySetInnerHTML/gi,
            /v-html\s*=/gi  // Vue.js XSS
        ]);

        // Path Traversal patterns
        this.patterns.set(VulnerabilityType.PATH_TRAVERSAL, [
            /readFile.*\+.*req\./gi,
            /readFileSync.*\+.*req\./gi,
            /path\.join\(.*req\./gi,
            /\.\.\/\.\.\//g
        ]);

        // Hardcoded secrets patterns
        this.patterns.set(VulnerabilityType.HARDCODED_SECRET, [
            /api[_-]?key\s*[:=]\s*['"`][A-Za-z0-9+/]{20,}/gi,
            /secret\s*[:=]\s*['"`][A-Za-z0-9+/]{20,}/gi,
            /password\s*[:=]\s*['"`].{8,}/gi,
            /token\s*[:=]\s*['"`][A-Za-z0-9+/]{20,}/gi,
            /private[_-]?key\s*[:=]\s*['"`]/gi
        ]);

        // Weak Cryptography patterns
        this.patterns.set(VulnerabilityType.WEAK_CRYPTO, [
            /createHash\s*\(\s*['"`]md5/gi,
            /createHash\s*\(\s*['"`]sha1/gi,
            /crypto\.createCipher\s*\(/gi,  // Deprecated weak cipher
            /Math\.random\s*\(\s*\).*password/gi,
            /Math\.random\s*\(\s*\).*token/gi
        ]);

        // Command Injection patterns
        this.patterns.set(VulnerabilityType.COMMAND_INJECTION, [
            /exec\s*\(.*\$\{/gi,
            /execSync\s*\(.*\+/gi,
            /spawn\s*\(.*\$\{/gi,
            /eval\s*\(.*req\./gi,
            /Function\s*\(.*req\./gi
        ]);
    }

    /**
     * Scan a file for vulnerabilities
     */
    public async scanFile(document: vscode.TextDocument): Promise<Vulnerability[]> {
        const text = document.getText();
        const lines = text.split('\n');
        const detectedVulnerabilities: Vulnerability[] = [];

        // Scan for each vulnerability type
        for (const [vulnType, patterns] of this.patterns) {
            for (const pattern of patterns) {
                const matches = this.findMatches(text, pattern);
                
                for (const match of matches) {
                    const position = this.getPositionFromOffset(lines, match.index);
                    
                    const vulnerability: Vulnerability = {
                        id: this.generateId(),
                        type: vulnType,
                        severity: this.calculateSeverity(vulnType),
                        line: position.line,
                        column: position.column,
                        message: this.getVulnerabilityMessage(vulnType),
                        file: document.fileName,
                        code: match.match,
                        recommendation: this.getRecommendation(vulnType),
                        educationalContent: this.getEducationalContent(vulnType)
                    };

                    detectedVulnerabilities.push(vulnerability);
                }
            }
        }

        this.vulnerabilities = detectedVulnerabilities;
        return detectedVulnerabilities;
    }

    /**
     * Find all matches for a pattern in text
     */
    private findMatches(text: string, pattern: RegExp): Array<{match: string, index: number}> {
        const matches: Array<{match: string, index: number}> = [];
        let match;

        // Reset the pattern lastIndex
        pattern.lastIndex = 0;

        while ((match = pattern.exec(text)) !== null) {
            matches.push({
                match: match[0],
                index: match.index
            });
        }

        return matches;
    }

    /**
     * Convert text offset to line and column
     */
    private getPositionFromOffset(lines: string[], offset: number): {line: number, column: number} {
        let currentOffset = 0;
        
        for (let i = 0; i < lines.length; i++) {
            if (currentOffset + lines[i].length >= offset) {
                return {
                    line: i + 1,
                    column: offset - currentOffset + 1
                };
            }
            currentOffset += lines[i].length + 1; // +1 for newline
        }

        return { line: 1, column: 1 };
    }

    /**
     * Calculate severity based on vulnerability type
     */
    private calculateSeverity(type: VulnerabilityType): 'low' | 'medium' | 'high' | 'critical' {
        switch (type) {
            case VulnerabilityType.SQL_INJECTION:
            case VulnerabilityType.COMMAND_INJECTION:
            case VulnerabilityType.PATH_TRAVERSAL:
                return 'critical';
            
            case VulnerabilityType.XSS:
            case VulnerabilityType.XXE:
            case VulnerabilityType.INSECURE_DESERIALIZATION:
                return 'high';
            
            case VulnerabilityType.HARDCODED_SECRET:
            case VulnerabilityType.WEAK_CRYPTO:
            case VulnerabilityType.SENSITIVE_DATA_EXPOSURE:
                return 'medium';
            
            default:
                return 'low';
        }
    }

    /**
     * Get descriptive message for vulnerability type
     */
    private getVulnerabilityMessage(type: VulnerabilityType): string {
        const messages: Record<VulnerabilityType, string> = {
            [VulnerabilityType.SQL_INJECTION]: 'Potential SQL injection vulnerability detected. User input is being concatenated directly into SQL query.',
            [VulnerabilityType.XSS]: 'Cross-site scripting vulnerability detected. User input is being rendered without proper sanitization.',
            [VulnerabilityType.PATH_TRAVERSAL]: 'Path traversal vulnerability detected. User input is being used to construct file paths.',
            [VulnerabilityType.INSECURE_RANDOM]: 'Insecure random number generation detected. Math.random() is not cryptographically secure.',
            [VulnerabilityType.HARDCODED_SECRET]: 'Hardcoded secret/credential detected. Sensitive information should be stored in environment variables.',
            [VulnerabilityType.WEAK_CRYPTO]: 'Weak cryptographic algorithm detected. Use stronger algorithms like SHA-256 or SHA-512.',
            [VulnerabilityType.COMMAND_INJECTION]: 'Command injection vulnerability detected. User input is being passed to system commands.',
            [VulnerabilityType.XXE]: 'XML External Entity vulnerability detected. XML parsing is vulnerable to XXE attacks.',
            [VulnerabilityType.INSECURE_DESERIALIZATION]: 'Insecure deserialization detected. Untrusted data is being deserialized.',
            [VulnerabilityType.SENSITIVE_DATA_EXPOSURE]: 'Sensitive data exposure detected. Sensitive information may be logged or transmitted insecurely.'
        };

        return messages[type] || 'Security vulnerability detected.';
    }

    /**
     * Get actionable recommendations for each vulnerability type
     * This is our key differentiator - providing clear, actionable fixes
     */
    private getRecommendation(type: VulnerabilityType): string {
        const recommendations: Record<VulnerabilityType, string> = {
            [VulnerabilityType.SQL_INJECTION]: 'Use parameterized queries or prepared statements. Example:\n```\nconst query = "SELECT * FROM users WHERE id = ?";\ndb.query(query, [userId]);\n```',
            [VulnerabilityType.XSS]: 'Sanitize user input before rendering. Use libraries like DOMPurify or encode HTML entities:\n```\nconst safe = DOMPurify.sanitize(userInput);\n```',
            [VulnerabilityType.PATH_TRAVERSAL]: 'Validate and sanitize file paths. Use path.resolve() and check if the resolved path is within allowed directory:\n```\nconst safePath = path.resolve(baseDir, userInput);\nif (!safePath.startsWith(baseDir)) throw new Error("Invalid path");\n```',
            [VulnerabilityType.INSECURE_RANDOM]: 'Use crypto.randomBytes() for cryptographically secure random values:\n```\nconst token = crypto.randomBytes(32).toString("hex");\n```',
            [VulnerabilityType.HARDCODED_SECRET]: 'Store secrets in environment variables:\n```\nconst apiKey = process.env.API_KEY;\n```\nUse .env files for local development and secure vaults for production.',
            [VulnerabilityType.WEAK_CRYPTO]: 'Use SHA-256 or stronger algorithms:\n```\ncrypto.createHash("sha256").update(data).digest("hex");\n```',
            [VulnerabilityType.COMMAND_INJECTION]: 'Avoid exec() with user input. Use spawn() with argument arrays:\n```\nconst { spawn } = require("child_process");\nspawn("ls", ["-la", userPath]);\n```',
            [VulnerabilityType.XXE]: 'Disable XML external entity processing:\n```\nparser.parseString(xml, { strict: true, explicitRoot: false });\n```',
            [VulnerabilityType.INSECURE_DESERIALIZATION]: 'Validate and sanitize data before deserialization. Use JSON schema validation.',
            [VulnerabilityType.SENSITIVE_DATA_EXPOSURE]: 'Encrypt sensitive data in transit and at rest. Use HTTPS and encryption libraries.'
        };

        return recommendations[type] || 'Review and fix this security issue.';
    }

    /**
     * Get educational content to help developers understand the vulnerability
     * This makes our tool educational, not just detective
     */
    private getEducationalContent(type: VulnerabilityType): string {
        const educational: Record<VulnerabilityType, string> = {
            [VulnerabilityType.SQL_INJECTION]: '**What is SQL Injection?**\nSQL injection occurs when untrusted data is inserted into SQL queries without proper validation. Attackers can manipulate queries to access unauthorized data or execute malicious commands.\n\n**Impact:** Data breach, data loss, unauthorized access\n**OWASP Ranking:** #3',
            [VulnerabilityType.XSS]: '**What is XSS?**\nCross-Site Scripting allows attackers to inject malicious scripts into web pages viewed by other users. This can steal cookies, session tokens, or redirect users to malicious sites.\n\n**Impact:** Session hijacking, defacement, malware distribution\n**OWASP Ranking:** #7',
            [VulnerabilityType.PATH_TRAVERSAL]: '**What is Path Traversal?**\nPath traversal attacks allow attackers to access files and directories outside the intended directory. Using "../" sequences, attackers can navigate to sensitive files.\n\n**Impact:** Unauthorized file access, data exposure\n**Prevention:** Input validation, sandboxing',
            [VulnerabilityType.HARDCODED_SECRET]: '**Why are hardcoded secrets dangerous?**\nHardcoded credentials in source code can be exposed through version control, making them accessible to anyone with repository access.\n\n**Best Practice:** Use environment variables, key management services, or secure vaults.',
            [VulnerabilityType.WEAK_CRYPTO]: '**Why avoid weak cryptography?**\nWeak algorithms like MD5 and SHA1 are vulnerable to collision attacks and can be broken with modern computing power.\n\n**Recommended:** Use SHA-256, SHA-512, or bcrypt for passwords.',
            [VulnerabilityType.COMMAND_INJECTION]: '**What is Command Injection?**\nCommand injection allows attackers to execute arbitrary system commands on the host operating system.\n\n**Impact:** Complete system compromise\n**Prevention:** Input validation, use safe APIs',
            [VulnerabilityType.INSECURE_RANDOM]: '**Why is Math.random() insecure?**\nMath.random() is predictable and not suitable for security purposes like generating tokens or passwords.\n\n**Use instead:** crypto.randomBytes() or crypto.getRandomValues()',
            [VulnerabilityType.XXE]: '**What is XXE?**\nXML External Entity attacks occur when XML input containing external entity references is processed by a weakly configured XML parser.\n\n**Impact:** File disclosure, SSRF, denial of service',
            [VulnerabilityType.INSECURE_DESERIALIZATION]: '**What is Insecure Deserialization?**\nDeserializing untrusted data can lead to remote code execution, replay attacks, injection attacks, and privilege escalation.\n\n**Prevention:** Input validation, integrity checks',
            [VulnerabilityType.SENSITIVE_DATA_EXPOSURE]: '**What is Sensitive Data Exposure?**\nOccurs when applications don\'t adequately protect sensitive information like passwords, credit cards, or personal data.\n\n**Prevention:** Encryption, secure protocols, data minimization'
        };

        return educational[type] || 'Security vulnerability that requires attention.';
    }

    /**
     * Generate unique ID for vulnerability
     */
    private generateId(): string {
        return `vuln_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Get all detected vulnerabilities
     */
    public getVulnerabilities(): Vulnerability[] {
        return this.vulnerabilities;
    }

    /**
     * Clear all vulnerabilities
     */
    public clearVulnerabilities(): void {
        this.vulnerabilities = [];
    }

    /**
     * Get vulnerabilities by severity
     */
    public getVulnerabilitiesBySeverity(severity: 'low' | 'medium' | 'high' | 'critical'): Vulnerability[] {
        return this.vulnerabilities.filter(v => v.severity === severity);
    }

    /**
     * Get vulnerability statistics
     */
    public getStatistics(): {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        byType: Record<string, number>;
    } {
        const stats = {
            total: this.vulnerabilities.length,
            critical: this.getVulnerabilitiesBySeverity('critical').length,
            high: this.getVulnerabilitiesBySeverity('high').length,
            medium: this.getVulnerabilitiesBySeverity('medium').length,
            low: this.getVulnerabilitiesBySeverity('low').length,
            byType: {} as Record<string, number>
        };

        // Count by type
        for (const vuln of this.vulnerabilities) {
            stats.byType[vuln.type] = (stats.byType[vuln.type] || 0) + 1;
        }

        return stats;
    }
}

export default SecurityScanner;