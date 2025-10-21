/**
 * Core Security Scanner Module
 * Detects vulnerabilities in code using ChatGPT API
 */

import * as vscode from 'vscode';
import { OpenAIClient, SecurityIssue } from '../ai/OpenAIClient';
import { RateLimiter, ScanCache, CodeChunker } from '../utils/RateLimiter';

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
    private openaiClient: OpenAIClient | null = null;
    private vulnerabilities: Vulnerability[] = [];
    private rateLimiter: RateLimiter;
    private cache: ScanCache<Vulnerability[]>;
    private chunker: CodeChunker;
    
    constructor(apiKey?: string) {
        if (apiKey) {
            // Explicitly use gpt-3.5-turbo for cost efficiency
            const model = process.env.OPENAI_MODEL || 'gpt-3.5-turbo';
            this.openaiClient = new OpenAIClient(apiKey, model);
            console.log(`SecurityScanner using model: ${model}`);
        }
        this.rateLimiter = new RateLimiter(20, 1000); // 20 requests per minute
        this.cache = new ScanCache(3600000); // 1 hour cache
        this.chunker = new CodeChunker(2000); // 2000 tokens per chunk
    }


    /**
     * Scan a file for vulnerabilities using ChatGPT
     */
    public async scanFile(document: vscode.TextDocument): Promise<Vulnerability[]> {
        if (!this.openaiClient) {
            vscode.window.showWarningMessage('OpenAI API key not configured. Using pattern-based detection.');
            return this.fallbackScan(document);
        }
        
        const text = document.getText();
        const language = document.languageId;
        
        // Check cache first
        const cached = this.cache.get(text);
        if (cached) {
            this.vulnerabilities = cached;
            return cached;
        }
        
        // Split into chunks if needed
        const chunks = this.chunker.splitIntoChunks(text);
        const allVulnerabilities: Vulnerability[] = [];
        
        // Scan each chunk with rate limiting
        for (let i = 0; i < chunks.length; i++) {
            await this.rateLimiter.waitIfNeeded();
            
            try {
                const issues = await this.openaiClient.analyzeCodeSecurity(chunks[i], language);
                const vulnerabilities = await this.convertToVulnerabilities(issues, document, i, chunks.length);
                allVulnerabilities.push(...vulnerabilities);
            } catch (error) {
                console.error(`Failed to scan chunk ${i + 1}:`, error);
            }
        }
        
        // Cache the results
        this.cache.set(text, allVulnerabilities);
        this.vulnerabilities = allVulnerabilities;
        
        return allVulnerabilities;
    }
    
    /**
     * Convert OpenAI issues to Vulnerability format
     */
    private async convertToVulnerabilities(
        issues: SecurityIssue[], 
        document: vscode.TextDocument, 
        chunkIndex: number, 
        totalChunks: number
    ): Promise<Vulnerability[]> {
        const vulnerabilities: Vulnerability[] = [];
        
        for (const issue of issues) {
            // Get educational content asynchronously
            const educational = issue.educational || 
                await this.openaiClient?.getEducationalContent(issue.type) || 
                this.getEducationalContent(this.mapToVulnerabilityType(issue.type));
            
            // Ensure line number is valid
            const lineNumber = typeof issue.line === 'number' ? issue.line : 1;
            const codeAtLine = this.getCodeAtLine(document, lineNumber);
            
            const vulnerability: Vulnerability = {
                id: this.generateId(),
                type: this.mapToVulnerabilityType(issue.type),
                severity: issue.severity,
                line: lineNumber,
                column: issue.column || 1,
                message: issue.description || `${issue.type} detected`,
                file: document.fileName,
                code: codeAtLine || `Line ${lineNumber}: ${issue.type}`,
                recommendation: issue.fix || this.getRecommendation(this.mapToVulnerabilityType(issue.type)),
                educationalContent: educational,
                automaticFix: issue.fix || '// Apply security fix here'
            };
            
            vulnerabilities.push(vulnerability);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Map string type to VulnerabilityType enum
     */
    private mapToVulnerabilityType(type: string): VulnerabilityType {
        const typeMap: Record<string, VulnerabilityType> = {
            'SQL Injection': VulnerabilityType.SQL_INJECTION,
            'XSS': VulnerabilityType.XSS,
            'Cross-Site Scripting': VulnerabilityType.XSS,
            'Path Traversal': VulnerabilityType.PATH_TRAVERSAL,
            'Command Injection': VulnerabilityType.COMMAND_INJECTION,
            'Hardcoded Secret': VulnerabilityType.HARDCODED_SECRET,
            'Weak Cryptography': VulnerabilityType.WEAK_CRYPTO,
            'XXE': VulnerabilityType.XXE,
            'Insecure Deserialization': VulnerabilityType.INSECURE_DESERIALIZATION,
            'Sensitive Data Exposure': VulnerabilityType.SENSITIVE_DATA_EXPOSURE
        };
        
        // Try exact match first
        if (typeMap[type]) {
            return typeMap[type];
        }
        
        // Try case-insensitive match
        const lowerType = type.toLowerCase();
        for (const [key, value] of Object.entries(typeMap)) {
            if (key.toLowerCase() === lowerType) {
                return value;
            }
        }
        
        // Default to sensitive data exposure for unknown types
        return VulnerabilityType.SENSITIVE_DATA_EXPOSURE;
    }
    
    /**
     * Get code at specific line
     */
    private getCodeAtLine(document: vscode.TextDocument, line: number): string {
        try {
            // Ensure line number is valid (1-based to 0-based conversion)
            const actualLine = Math.max(0, Math.min(document.lineCount - 1, line - 1));
            const textLine = document.lineAt(actualLine);
            return textLine.text.trim();
        } catch (error) {
            console.error(`Failed to get code at line ${line}:`, error);
            // Try to get some context around the line
            try {
                const startLine = Math.max(0, line - 2);
                const endLine = Math.min(document.lineCount - 1, line);
                let code = '';
                for (let i = startLine; i <= endLine; i++) {
                    code += document.lineAt(i).text + '\n';
                }
                return code.trim();
            } catch {
                return 'Unable to retrieve code';
            }
        }
    }
    
    /**
     * Fallback to pattern-based scanning when API is not available
     */
    private fallbackScan(document: vscode.TextDocument): Vulnerability[] {
        // Basic pattern-based detection as fallback
        const text = document.getText();
        const vulnerabilities: Vulnerability[] = [];
        
        // Simple SQL injection check
        const sqlPattern = /query\s*\(.*\+.*['"`]/gi;
        let match;
        while ((match = sqlPattern.exec(text)) !== null) {
            vulnerabilities.push({
                id: this.generateId(),
                type: VulnerabilityType.SQL_INJECTION,
                severity: 'high',
                line: this.getLineFromOffset(text, match.index),
                column: 1,
                message: 'Potential SQL injection detected',
                file: document.fileName,
                code: match[0],
                recommendation: 'Use parameterized queries',
                educationalContent: this.getEducationalContent(VulnerabilityType.SQL_INJECTION)
            });
        }
        
        return vulnerabilities;
    }
    
    /**
     * Get line number from text offset
     */
    private getLineFromOffset(text: string, offset: number): number {
        const lines = text.substring(0, offset).split('\n');
        return lines.length;
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