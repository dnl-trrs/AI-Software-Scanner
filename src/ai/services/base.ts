/**
 * Base interfaces for AI services
 */

export interface AIServiceConfig {
    apiKey: string;
    maxRequestsPerMinute: number;
    maxTokens?: number;
    temperature?: number;
}

export interface AIAnalysisRequest {
    code: string;
    language: string;
    context?: string;
}

export interface AIAnalysisResponse {
    issues: AISecurityIssue[];
    confidence: number;
    suggestions?: string[];
    error?: string;
}

export interface AISecurityIssue {
    type: string;
    severity: 'info' | 'warning' | 'error';
    message: string;
    line: number;
    column: number;
    endLine?: number;
    endColumn?: number;
    cwe?: string; // Common Weakness Enumeration ID
    description: string;
    remediation: string;
}

export interface AIService {
    analyze(request: AIAnalysisRequest): Promise<AIAnalysisResponse>;
    isReady(): boolean;
    getRequestsRemaining(): number;
}