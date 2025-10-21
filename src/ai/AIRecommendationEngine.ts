/**
 * AI Recommendation Engine
 * Provides intelligent, context-aware fix suggestions and educational content using ChatGPT
 */

import { Vulnerability, VulnerabilityType } from '../scanner/SecurityScanner';
import { OpenAIClient } from './OpenAIClient';
import { RateLimiter } from '../utils/RateLimiter';

export interface AIRecommendation {
    vulnerabilityId: string;
    automaticFix: string;
    explanation: string;
    bestPractices: string[];
    alternativeSolutions: string[];
    estimatedFixTime: number; // in minutes
    confidence: number; // 0-100
    learningResources: LearningResource[];
}

export interface LearningResource {
    title: string;
    type: 'article' | 'video' | 'documentation' | 'tutorial';
    url: string;
    difficulty: 'beginner' | 'intermediate' | 'advanced';
}

export class AIRecommendationEngine {
    private openaiClient: OpenAIClient | null = null;
    private rateLimiter: RateLimiter;
    private useLocalModel: boolean = false; // Use ChatGPT when available

    constructor(apiKey?: string) {
        if (apiKey) {
            // Explicitly use gpt-3.5-turbo for cost efficiency
            const model = process.env.OPENAI_MODEL || 'gpt-3.5-turbo';
            this.openaiClient = new OpenAIClient(apiKey, model);
            this.useLocalModel = false;
            console.log(`AIRecommendationEngine using model: ${model}`);
        } else {
            this.useLocalModel = true;
        }
        this.rateLimiter = new RateLimiter(15, 1000); // 15 requests per minute for recommendations
    }

    /**
     * Generate AI-powered recommendation for a vulnerability
     * This provides the actionable, developer-friendly fixes that differentiate us
     */
    public async generateRecommendation(vulnerability: Vulnerability, context?: string): Promise<AIRecommendation> {
        // For now, use enhanced local patterns. In production, this would call OpenAI/Claude
        if (this.useLocalModel) {
            return this.generateLocalRecommendation(vulnerability, context);
        }
        
        // Future: Call external AI service
        return this.callAIService(vulnerability, context);
    }

    /**
     * Generate recommendation using local knowledge base
     * This provides immediate value without requiring API keys
     */
    private async generateLocalRecommendation(vulnerability: Vulnerability, context?: string): Promise<AIRecommendation> {
        const automaticFix = this.generateAutomaticFix(vulnerability, context);
        const explanation = this.generateDetailedExplanation(vulnerability);
        const bestPractices = this.getBestPractices(vulnerability.type);
        const alternatives = this.getAlternativeSolutions(vulnerability.type);
        const resources = this.getLearningResources(vulnerability.type);

        return {
            vulnerabilityId: vulnerability.id,
            automaticFix,
            explanation,
            bestPractices,
            alternativeSolutions: alternatives,
            estimatedFixTime: this.estimateFixTime(vulnerability.type),
            confidence: this.calculateConfidence(vulnerability),
            learningResources: resources
        };
    }

    /**
     * Generate automatic fix code for the vulnerability
     * This is what makes our solution actionable, not just detective
     */
    private generateAutomaticFix(vulnerability: Vulnerability, context?: string): string {
        const fixes: Record<VulnerabilityType, (code: string) => string> = {
            [VulnerabilityType.SQL_INJECTION]: (code: string) => {
                // Transform SQL concatenation to parameterized query
                if (code.includes('query(')) {
                    return code
                        .replace(/query\s*\(\s*['"`](.*?)\s*\+\s*(.*?)['"`]\s*\)/g, 
                                'query("$1", [$2])')
                        .replace(/\$\{(.*?)\}/g, '?');
                }
                return `// Use parameterized query instead:\nconst query = 'SELECT * FROM users WHERE id = ?';\ndb.query(query, [userId]);`;
            },

            [VulnerabilityType.XSS]: (code: string) => {
                // Add sanitization to innerHTML assignments
                if (code.includes('innerHTML')) {
                    return `import DOMPurify from 'dompurify';\n${code.replace(
                        /innerHTML\s*=\s*(.*);/g,
                        'innerHTML = DOMPurify.sanitize($1);'
                    )}`;
                }
                return `// Sanitize user input:\nimport DOMPurify from 'dompurify';\nelement.innerHTML = DOMPurify.sanitize(userInput);`;
            },

            [VulnerabilityType.PATH_TRAVERSAL]: (code: string) => {
                return `import path from 'path';\n\n// Sanitize and validate path\nconst basePath = '/safe/directory';\nconst userPath = path.normalize(userInput);\nconst fullPath = path.resolve(basePath, userPath);\n\nif (!fullPath.startsWith(basePath)) {\n    throw new Error('Invalid path: Access denied');\n}\n\n// Safe to use fullPath now`;
            },

            [VulnerabilityType.HARDCODED_SECRET]: (code: string) => {
                // Replace hardcoded values with environment variables
                const fixed = code
                    .replace(/api[_-]?key\s*[:=]\s*['"`][^'"`]+['"`]/gi, 'apiKey: process.env.API_KEY')
                    .replace(/password\s*[:=]\s*['"`][^'"`]+['"`]/gi, 'password: process.env.PASSWORD')
                    .replace(/secret\s*[:=]\s*['"`][^'"`]+['"`]/gi, 'secret: process.env.SECRET_KEY');
                
                return `// Move secrets to environment variables:\n// 1. Create .env file (don't commit to git)\n// 2. Add: API_KEY=your_actual_key\n// 3. Use dotenv package:\nrequire('dotenv').config();\n\n${fixed}`;
            },

            [VulnerabilityType.WEAK_CRYPTO]: (code: string) => {
                return code
                    .replace(/createHash\s*\(\s*['"`]md5['"`]\)/g, 'createHash("sha256")')
                    .replace(/createHash\s*\(\s*['"`]sha1['"`]\)/g, 'createHash("sha256")')
                    .replace(/crypto\.createCipher/g, 'crypto.createCipheriv');
            },

            [VulnerabilityType.COMMAND_INJECTION]: (code: string) => {
                return `// Use spawn with argument array instead of exec:\nconst { spawn } = require('child_process');\n\n// BAD: exec(\`ls \${userInput}\`)\n// GOOD:\nconst child = spawn('ls', [userInput], {\n    shell: false  // Disable shell interpretation\n});\n\nchild.stdout.on('data', (data) => {\n    console.log(data.toString());\n});`;
            },

            [VulnerabilityType.INSECURE_RANDOM]: (code: string) => {
                return code.replace(
                    /Math\.random\(\)/g,
                    'crypto.randomBytes(32).toString("hex")'
                );
            },

            [VulnerabilityType.XXE]: (code: string) => {
                return `// Disable external entities in XML parser:\nconst parser = new xml2js.Parser({\n    strict: true,\n    explicitRoot: false,\n    ignoreAttrs: false,\n    mergeAttrs: false,\n    explicitArray: false,\n    // Disable external entity processing\n    xmlnsStrict: true,\n    xmlns: false,\n    allowDtd: false\n});\n\nparser.parseString(xmlData, (err, result) => {\n    if (err) throw err;\n    // Process safe XML\n});`;
            },

            [VulnerabilityType.INSECURE_DESERIALIZATION]: (code: string) => {
                return `// Validate data before deserialization:\nimport Ajv from 'ajv';\n\nconst schema = {\n    type: 'object',\n    properties: {\n        id: { type: 'number' },\n        name: { type: 'string' }\n    },\n    required: ['id', 'name'],\n    additionalProperties: false\n};\n\nconst ajv = new Ajv();\nconst validate = ajv.compile(schema);\n\nif (validate(data)) {\n    // Safe to use validated data\n    const obj = JSON.parse(JSON.stringify(data));\n} else {\n    throw new Error('Invalid data structure');\n}`;
            },

            [VulnerabilityType.SENSITIVE_DATA_EXPOSURE]: (code: string) => {
                return `// Encrypt sensitive data:\nimport crypto from 'crypto';\n\nconst algorithm = 'aes-256-gcm';\nconst key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');\nconst iv = crypto.randomBytes(16);\n\nfunction encrypt(text) {\n    const cipher = crypto.createCipheriv(algorithm, key, iv);\n    let encrypted = cipher.update(text, 'utf8', 'hex');\n    encrypted += cipher.final('hex');\n    const authTag = cipher.getAuthTag();\n    return { encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };\n}`;
            }
        };

        const fixFunction = fixes[vulnerability.type];
        return fixFunction ? fixFunction(vulnerability.code) : '// Manual review required';
    }

    /**
     * Generate detailed explanation of the vulnerability and fix
     * This provides the educational aspect that competitors lack
     */
    private generateDetailedExplanation(vulnerability: Vulnerability): string {
        const explanations: Record<VulnerabilityType, string> = {
            [VulnerabilityType.SQL_INJECTION]: `This SQL injection vulnerability occurs because user input is directly concatenated into the SQL query string. An attacker could inject malicious SQL code to:\n• Access unauthorized data\n• Modify or delete database records\n• Execute administrative operations\n\nThe fix uses parameterized queries, which separate SQL logic from data, making injection impossible.`,

            [VulnerabilityType.XSS]: `This XSS vulnerability allows attackers to inject malicious JavaScript that executes in other users' browsers. The impact includes:\n• Stealing session cookies\n• Performing actions on behalf of users\n• Defacing the website\n\nThe fix sanitizes HTML content using DOMPurify, which removes dangerous elements while preserving safe HTML.`,

            [VulnerabilityType.PATH_TRAVERSAL]: `Path traversal vulnerabilities let attackers access files outside the intended directory using "../" sequences. This could expose:\n• Source code\n• Configuration files\n• System files\n\nThe fix validates paths using path.resolve() and ensures they stay within the allowed directory.`,

            [VulnerabilityType.HARDCODED_SECRET]: `Hardcoded secrets in source code are visible to anyone with repository access. This includes:\n• Current and former employees\n• Anyone if the repo becomes public\n• Attackers who gain repository access\n\nThe fix moves secrets to environment variables, keeping them separate from code.`,

            [VulnerabilityType.WEAK_CRYPTO]: `Weak cryptographic algorithms like MD5 and SHA1 are vulnerable to:\n• Collision attacks (two inputs producing same hash)\n• Rainbow table attacks\n• Brute force with modern hardware\n\nThe fix upgrades to SHA-256, which provides adequate security for current computing capabilities.`,

            [VulnerabilityType.COMMAND_INJECTION]: `Command injection allows attackers to execute arbitrary system commands, potentially:\n• Taking full control of the server\n• Accessing sensitive files\n• Pivoting to internal networks\n\nThe fix uses spawn() with argument arrays, preventing shell interpretation of user input.`,

            [VulnerabilityType.INSECURE_RANDOM]: `Math.random() is predictable and unsuitable for security purposes. Attackers could:\n• Predict session tokens\n• Guess password reset tokens\n• Break other security mechanisms\n\nThe fix uses crypto.randomBytes(), which provides cryptographically secure randomness.`,

            [VulnerabilityType.XXE]: `XXE attacks exploit XML parsers to:\n• Read local files\n• Perform server-side request forgery\n• Cause denial of service\n\nThe fix disables external entity processing in the XML parser configuration.`,

            [VulnerabilityType.INSECURE_DESERIALIZATION]: `Deserializing untrusted data can lead to:\n• Remote code execution\n• Privilege escalation\n• Data tampering\n\nThe fix validates data structure before deserialization using JSON schema.`,

            [VulnerabilityType.SENSITIVE_DATA_EXPOSURE]: `Sensitive data exposure occurs when applications don't protect data like:\n• Passwords and tokens\n• Credit card numbers\n• Personal information\n\nThe fix implements encryption for sensitive data using AES-256-GCM.`
        };

        return explanations[vulnerability.type] || 'This vulnerability requires immediate attention and manual review.';
    }

    /**
     * Get best practices for preventing this type of vulnerability
     */
    private getBestPractices(type: VulnerabilityType): string[] {
        const practices: Record<VulnerabilityType, string[]> = {
            [VulnerabilityType.SQL_INJECTION]: [
                'Always use parameterized queries or prepared statements',
                'Validate and sanitize all user input',
                'Use stored procedures where appropriate',
                'Apply principle of least privilege to database accounts',
                'Use an ORM that handles parameterization automatically'
            ],
            [VulnerabilityType.XSS]: [
                'Sanitize all user input before rendering',
                'Use Content Security Policy (CSP) headers',
                'Encode output based on context (HTML, JavaScript, CSS)',
                'Use framework auto-escaping features',
                'Validate input on both client and server side'
            ],
            [VulnerabilityType.PATH_TRAVERSAL]: [
                'Validate and sanitize file paths',
                'Use a whitelist of allowed files/directories',
                'Avoid user input in file operations when possible',
                'Run applications with minimal file system permissions',
                'Use chroot jails or containers for isolation'
            ],
            [VulnerabilityType.HARDCODED_SECRET]: [
                'Store secrets in environment variables',
                'Use secret management services (Vault, AWS Secrets Manager)',
                'Rotate secrets regularly',
                'Never commit secrets to version control',
                'Use .gitignore for environment files'
            ],
            [VulnerabilityType.WEAK_CRYPTO]: [
                'Use industry-standard algorithms (AES, SHA-256)',
                'Keep cryptographic libraries updated',
                'Use appropriate key sizes (256-bit for AES)',
                'Never implement custom cryptography',
                'Use bcrypt or Argon2 for password hashing'
            ],
            [VulnerabilityType.COMMAND_INJECTION]: [
                'Avoid system commands when possible',
                'Use language-specific libraries instead of shell commands',
                'If commands are necessary, use parameterized APIs',
                'Validate and sanitize all input',
                'Run with minimal system privileges'
            ],
            [VulnerabilityType.INSECURE_RANDOM]: [
                'Use crypto.randomBytes() for security-critical randomness',
                'Never use Math.random() for security purposes',
                'Use appropriate entropy sources',
                'Consider using UUIDs for unique identifiers',
                'Test randomness quality in security-critical applications'
            ],
            [VulnerabilityType.XXE]: [
                'Disable external entity processing by default',
                'Use JSON instead of XML when possible',
                'Validate XML against a schema',
                'Keep XML parsers updated',
                'Use safe parser configurations'
            ],
            [VulnerabilityType.INSECURE_DESERIALIZATION]: [
                'Validate data before deserialization',
                'Use simple data formats (JSON) over complex ones',
                'Implement integrity checks (HMAC)',
                'Avoid deserializing data from untrusted sources',
                'Use allowlists for acceptable classes/types'
            ],
            [VulnerabilityType.SENSITIVE_DATA_EXPOSURE]: [
                'Encrypt sensitive data at rest and in transit',
                'Use HTTPS for all communications',
                'Implement proper key management',
                'Minimize data retention',
                'Follow data protection regulations (GDPR, CCPA)'
            ]
        };

        return practices[type] || ['Review security best practices for this vulnerability type'];
    }

    /**
     * Get alternative solutions for fixing the vulnerability
     */
    private getAlternativeSolutions(type: VulnerabilityType): string[] {
        const alternatives: Record<VulnerabilityType, string[]> = {
            [VulnerabilityType.SQL_INJECTION]: [
                'Use an ORM like Sequelize or TypeORM',
                'Implement stored procedures',
                'Use query builders with automatic escaping',
                'Apply input validation with strict patterns'
            ],
            [VulnerabilityType.XSS]: [
                'Use React/Vue/Angular with automatic escaping',
                'Implement Content Security Policy',
                'Use template engines with auto-escaping',
                'Apply HTML sanitization libraries'
            ],
            [VulnerabilityType.HARDCODED_SECRET]: [
                'Use AWS Secrets Manager',
                'Implement HashiCorp Vault',
                'Use Azure Key Vault',
                'Apply Kubernetes secrets'
            ],
            // Add more alternatives for other types...
            [VulnerabilityType.PATH_TRAVERSAL]: [
                'Use a CDN for static files',
                'Implement a file access API with validation',
                'Use symbolic links with restricted permissions'
            ],
            [VulnerabilityType.WEAK_CRYPTO]: [
                'Use bcrypt for passwords',
                'Implement Argon2 for sensitive hashing',
                'Use hardware security modules (HSM)'
            ],
            [VulnerabilityType.COMMAND_INJECTION]: [
                'Use library functions instead of system commands',
                'Implement a restricted command API',
                'Use containers with limited capabilities'
            ],
            [VulnerabilityType.INSECURE_RANDOM]: [
                'Use hardware random number generators',
                'Implement /dev/urandom on Linux',
                'Use Web Crypto API in browsers'
            ],
            [VulnerabilityType.XXE]: [
                'Switch to JSON format',
                'Use YAML for configuration',
                'Implement Protocol Buffers'
            ],
            [VulnerabilityType.INSECURE_DESERIALIZATION]: [
                'Use JSON with schema validation',
                'Implement Protocol Buffers',
                'Use MessagePack with validation'
            ],
            [VulnerabilityType.SENSITIVE_DATA_EXPOSURE]: [
                'Implement field-level encryption',
                'Use tokenization for sensitive data',
                'Apply data masking techniques'
            ]
        };

        return alternatives[type] || ['Consider alternative implementations'];
    }

    /**
     * Get learning resources for developers
     * This educational aspect sets us apart from competitors
     */
    private getLearningResources(type: VulnerabilityType): LearningResource[] {
        const baseResources: LearningResource[] = [
            {
                title: 'OWASP Top 10',
                type: 'documentation',
                url: 'https://owasp.org/www-project-top-ten/',
                difficulty: 'beginner'
            },
            {
                title: 'Secure Coding Practices',
                type: 'article',
                url: 'https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/',
                difficulty: 'intermediate'
            }
        ];

        const specificResources: Record<VulnerabilityType, LearningResource[]> = {
            [VulnerabilityType.SQL_INJECTION]: [
                {
                    title: 'SQL Injection Prevention Cheat Sheet',
                    type: 'documentation',
                    url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
                    difficulty: 'intermediate'
                },
                {
                    title: 'Understanding SQL Injection',
                    type: 'video',
                    url: 'https://www.youtube.com/watch?v=ciNHn38EyRc',
                    difficulty: 'beginner'
                }
            ],
            [VulnerabilityType.XSS]: [
                {
                    title: 'XSS Prevention Cheat Sheet',
                    type: 'documentation',
                    url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
                    difficulty: 'intermediate'
                },
                {
                    title: 'XSS Attack Vectors',
                    type: 'tutorial',
                    url: 'https://portswigger.net/web-security/cross-site-scripting',
                    difficulty: 'advanced'
                }
            ],
            // Add resources for other vulnerability types...
            [VulnerabilityType.PATH_TRAVERSAL]: [
                {
                    title: 'Path Traversal Prevention',
                    type: 'article',
                    url: 'https://owasp.org/www-community/attacks/Path_Traversal',
                    difficulty: 'intermediate'
                }
            ],
            [VulnerabilityType.HARDCODED_SECRET]: [
                {
                    title: 'Secrets Management Best Practices',
                    type: 'article',
                    url: 'https://www.gitguardian.com/secrets-detection',
                    difficulty: 'beginner'
                }
            ],
            [VulnerabilityType.WEAK_CRYPTO]: [
                {
                    title: 'Cryptographic Best Practices',
                    type: 'documentation',
                    url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
                    difficulty: 'advanced'
                }
            ],
            [VulnerabilityType.COMMAND_INJECTION]: [
                {
                    title: 'Command Injection Prevention',
                    type: 'article',
                    url: 'https://owasp.org/www-community/attacks/Command_Injection',
                    difficulty: 'intermediate'
                }
            ],
            [VulnerabilityType.INSECURE_RANDOM]: [
                {
                    title: 'Secure Random Number Generation',
                    type: 'article',
                    url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation',
                    difficulty: 'intermediate'
                }
            ],
            [VulnerabilityType.XXE]: [
                {
                    title: 'XXE Prevention',
                    type: 'documentation',
                    url: 'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
                    difficulty: 'advanced'
                }
            ],
            [VulnerabilityType.INSECURE_DESERIALIZATION]: [
                {
                    title: 'Deserialization Security',
                    type: 'article',
                    url: 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
                    difficulty: 'advanced'
                }
            ],
            [VulnerabilityType.SENSITIVE_DATA_EXPOSURE]: [
                {
                    title: 'Data Protection Guide',
                    type: 'documentation',
                    url: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
                    difficulty: 'intermediate'
                }
            ]
        };

        return [...baseResources, ...(specificResources[type] || [])];
    }

    /**
     * Estimate time to fix the vulnerability
     */
    private estimateFixTime(type: VulnerabilityType): number {
        const estimates: Record<VulnerabilityType, number> = {
            [VulnerabilityType.SQL_INJECTION]: 30,
            [VulnerabilityType.XSS]: 20,
            [VulnerabilityType.PATH_TRAVERSAL]: 25,
            [VulnerabilityType.HARDCODED_SECRET]: 10,
            [VulnerabilityType.WEAK_CRYPTO]: 15,
            [VulnerabilityType.COMMAND_INJECTION]: 35,
            [VulnerabilityType.INSECURE_RANDOM]: 10,
            [VulnerabilityType.XXE]: 30,
            [VulnerabilityType.INSECURE_DESERIALIZATION]: 40,
            [VulnerabilityType.SENSITIVE_DATA_EXPOSURE]: 45
        };

        return estimates[type] || 30;
    }

    /**
     * Calculate confidence in the recommendation
     */
    private calculateConfidence(vulnerability: Vulnerability): number {
        // Base confidence on pattern match strength and context availability
        let confidence = 70;

        // Adjust based on severity (higher severity = more confident in the need to fix)
        switch (vulnerability.severity) {
            case 'critical': confidence += 20; break;
            case 'high': confidence += 15; break;
            case 'medium': confidence += 10; break;
            case 'low': confidence += 5; break;
        }

        // Cap at 95% (never 100% certain without human review)
        return Math.min(confidence, 95);
    }

    /**
     * Call ChatGPT API for enhanced recommendations
     */
    private async callAIService(vulnerability: Vulnerability, context?: string): Promise<AIRecommendation> {
        if (!this.openaiClient) {
            return this.generateLocalRecommendation(vulnerability, context);
        }

        try {
            await this.rateLimiter.waitIfNeeded();
            
            // Get enhanced fix from ChatGPT
            const automaticFix = await this.openaiClient.generateFix(
                {
                    type: vulnerability.type,
                    severity: vulnerability.severity,
                    line: vulnerability.line,
                    description: vulnerability.message,
                    fix: vulnerability.recommendation || '',
                    educational: vulnerability.educationalContent
                },
                context || vulnerability.code
            );
            
            // Get educational content
            const educational = await this.openaiClient.getEducationalContent(vulnerability.type);
            
            return {
                vulnerabilityId: vulnerability.id,
                automaticFix,
                explanation: educational,
                bestPractices: this.getBestPractices(vulnerability.type),
                alternativeSolutions: this.getAlternativeSolutions(vulnerability.type),
                estimatedFixTime: this.estimateFixTime(vulnerability.type),
                confidence: 85, // Higher confidence with AI
                learningResources: this.getLearningResources(vulnerability.type)
            };
        } catch (error) {
            console.error('ChatGPT API error, falling back to local:', error);
            return this.generateLocalRecommendation(vulnerability, context);
        }
    }

    /**
     * Batch process multiple vulnerabilities for efficiency
     */
    public async generateBatchRecommendations(vulnerabilities: Vulnerability[]): Promise<AIRecommendation[]> {
        const recommendations = await Promise.all(
            vulnerabilities.map(vuln => this.generateRecommendation(vuln))
        );
        return recommendations;
    }

    /**
     * Get a summary of all recommendations
     */
    public generateSummary(recommendations: AIRecommendation[]): {
        totalFixTime: number;
        averageConfidence: number;
        priorityOrder: AIRecommendation[];
        learningPath: LearningResource[];
    } {
        const totalFixTime = recommendations.reduce((sum, rec) => sum + rec.estimatedFixTime, 0);
        const averageConfidence = recommendations.reduce((sum, rec) => sum + rec.confidence, 0) / recommendations.length;
        
        // Sort by confidence and severity for priority
        const priorityOrder = [...recommendations].sort((a, b) => b.confidence - a.confidence);
        
        // Collect unique learning resources
        const learningPath = Array.from(
            new Map(
                recommendations
                    .flatMap(rec => rec.learningResources)
                    .map(resource => [resource.url, resource])
            ).values()
        );

        return {
            totalFixTime,
            averageConfidence: Math.round(averageConfidence),
            priorityOrder,
            learningPath
        };
    }
}

export default AIRecommendationEngine;