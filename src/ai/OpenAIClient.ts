import OpenAI from 'openai';
import * as vscode from 'vscode';

export interface SecurityIssue {
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    line: number;
    column?: number;
    description: string;
    fix: string;
    educational?: string;
}

export class OpenAIClient {
    private client: OpenAI;
    private model: string;
    
    constructor(apiKey: string, model: string = 'gpt-3.5-turbo') {
        this.client = new OpenAI({
            apiKey: apiKey
        });
        this.model = model;
    }
    
    /**
     * Analyze code for security vulnerabilities
     */
    async analyzeCodeSecurity(code: string, language: string): Promise<SecurityIssue[]> {
        try {
            const response = await this.client.chat.completions.create({
                model: this.model,
                messages: [
                    {
                        role: "system",
                        content: `You are a security expert analyzing ${language} code. 
                        Identify security vulnerabilities and return a JSON array with this exact structure:
                        {
                            "vulnerabilities": [
                                {
                                    "type": "vulnerability type (e.g., SQL Injection, XSS, etc.)",
                                    "severity": "critical|high|medium|low",
                                    "line": line_number_integer,
                                    "description": "clear description of the issue",
                                    "fix": "suggested fix code or approach",
                                    "educational": "brief explanation of why this is a security issue"
                                }
                            ]
                        }
                        Be specific about line numbers and provide actionable fixes.`
                    },
                    {
                        role: "user",
                        content: `Analyze this code for security vulnerabilities:\n\n${code}`
                    }
                ],
                response_format: { type: "json_object" },
                temperature: 0.2,
                max_tokens: 1500
            });
            
            const content = response.choices[0].message.content || '{"vulnerabilities": []}';
            
            // Try to fix common JSON issues
            let cleanedContent = content
                .replace(/\n/g, ' ')  // Remove newlines that might break JSON
                .replace(/,\s*}/g, '}')  // Remove trailing commas
                .replace(/,\s*]/g, ']')  // Remove trailing commas in arrays
                .trim();
            
            try {
                const result = JSON.parse(cleanedContent);
                // Ensure line numbers are integers
                if (result.vulnerabilities && Array.isArray(result.vulnerabilities)) {
                    return result.vulnerabilities.map((vuln: any) => ({
                        ...vuln,
                        line: parseInt(vuln.line) || 1,
                        column: parseInt(vuln.column) || 1
                    }));
                }
                return result.vulnerabilities || [];
            } catch (parseError) {
                console.error('JSON parse error:', parseError);
                console.error('Raw content:', content.substring(0, 500));
                
                // Fallback: try to extract vulnerabilities manually
                const fallbackVulnerabilities: SecurityIssue[] = [];
                
                // Simple pattern matching as fallback
                if (content.includes('SQL') || content.includes('injection')) {
                    fallbackVulnerabilities.push({
                        type: 'SQL Injection',
                        severity: 'high',
                        line: 1,
                        description: 'Potential SQL injection detected',
                        fix: 'Use parameterized queries',
                        educational: 'SQL injection can lead to data breach'
                    });
                }
                
                return fallbackVulnerabilities;
            }
        } catch (error) {
            console.error('OpenAI API error:', error);
            vscode.window.showErrorMessage(`Security scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
            return [];
        }
    }
    
    /**
     * Generate detailed fix recommendations
     */
    async generateFix(vulnerability: SecurityIssue, context: string): Promise<string> {
        try {
            const response = await this.client.chat.completions.create({
                model: this.model,
                messages: [
                    {
                        role: "system",
                        content: "You are a security expert providing detailed code fixes. Provide complete, production-ready code that addresses the security issue."
                    },
                    {
                        role: "user",
                        content: `Fix this ${vulnerability.type} vulnerability:
                        
                        Issue: ${vulnerability.description}
                        Severity: ${vulnerability.severity}
                        
                        Context code:
                        ${context}
                        
                        Provide the complete fixed code.`
                    }
                ],
                temperature: 0.3,
                max_tokens: 1000
            });
            
            return response.choices[0].message.content || vulnerability.fix;
        } catch (error) {
            console.error('Failed to generate fix:', error);
            return vulnerability.fix; // Fall back to original fix
        }
    }
    
    /**
     * Generate educational content about a vulnerability type
     */
    async getEducationalContent(vulnerabilityType: string): Promise<string> {
        try {
            const response = await this.client.chat.completions.create({
                model: this.model,
                messages: [
                    {
                        role: "system",
                        content: "You are a security educator. Provide concise, educational content about security vulnerabilities in a friendly, informative tone."
                    },
                    {
                        role: "user",
                        content: `Explain the ${vulnerabilityType} vulnerability:
                        - What is it?
                        - Why is it dangerous?
                        - How to prevent it?
                        - Real-world impact examples
                        
                        Keep it under 200 words and practical.`
                    }
                ],
                temperature: 0.5,
                max_tokens: 400
            });
            
            return response.choices[0].message.content || `Learn more about ${vulnerabilityType} vulnerabilities.`;
        } catch (error) {
            console.error('Failed to get educational content:', error);
            return `${vulnerabilityType} is a security vulnerability that should be addressed.`;
        }
    }
    
    /**
     * Check if API key is valid
     */
    async testConnection(): Promise<boolean> {
        try {
            const response = await this.client.chat.completions.create({
                model: this.model,
                messages: [{ role: "user", content: "test" }],
                max_tokens: 5
            });
            return true;
        } catch (error) {
            return false;
        }
    }
}