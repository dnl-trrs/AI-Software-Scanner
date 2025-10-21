import OpenAI from 'openai';
import { AIService, AIServiceConfig, AIAnalysisRequest, AIAnalysisResponse } from './base';
import { Logger } from '../../utils';
import { AnalysisPipeline } from '../pipeline';
import * as vscode from 'vscode';

export class OpenAIService implements AIService {
    private api!: OpenAI;
    private config: AIServiceConfig;
    private rateLimiter: RateLimiter;
    private ready: boolean = false;

    constructor(config: AIServiceConfig) {
        this.config = config;
        this.rateLimiter = new RateLimiter(config.maxRequestsPerMinute);
        this.initializeAPI();
    }

    private initializeAPI() {
        try {
            this.api = new OpenAI({
                apiKey: this.config.apiKey
            });
            this.ready = true;
            Logger.info('OpenAI API initialized successfully');
        } catch (error) {
            Logger.error('Failed to initialize OpenAI API', error as Error);
            this.ready = false;
        }
    }

    public isReady(): boolean {
        return this.ready && this.rateLimiter.hasRequests();
    }

    public getRequestsRemaining(): number {
        return this.rateLimiter.getRequestsRemaining();
    }

    public async analyze(request: AIAnalysisRequest): Promise<AIAnalysisResponse> {
        if (!this.isReady()) {
            throw new Error('AI service is not ready or rate limit exceeded');
        }

        try {
            // Wait for rate limiter
            await this.rateLimiter.waitForAvailability();

            // Get the active document
            const currentDoc = vscode.window.activeTextEditor?.document;
            if (!currentDoc) {
                throw new Error('No active document found');
            }

            // Preprocess code
            const processed = await AnalysisPipeline.preprocessCode(currentDoc);

            // Generate the analysis prompt with context
            const prompt = this.generatePrompt({
                ...request,
                code: processed.code,
                context: JSON.stringify(processed.context)
            });

            // Make API call
            const completion = await this.api.chat.completions.create({
                model: "gpt-4",
                messages: [
                    {
                        role: "system",
                        content: "You are a cybersecurity expert analyzing code for security vulnerabilities. Provide detailed analysis of potential security issues, including CWE IDs, severity levels, and specific remediation advice."
                    },
                    {
                        role: "user",
                        content: prompt
                    }
                ],
                max_tokens: this.config.maxTokens || 2000,
                temperature: this.config.temperature || 0.3,
            });

            // Get initial results
            const initialResults = this.parseResponse(completion.choices[0].message?.content || '');

            // Get the document for context
            const activeDoc = vscode.window.activeTextEditor?.document;
            if (!activeDoc) {
                return initialResults;
            }

            // Process results with context
            const processedResults = AnalysisPipeline.processResults(
                initialResults,
                await AnalysisPipeline.preprocessCode(activeDoc)
            );

            return processedResults;

        } catch (error) {
            Logger.error('Error during OpenAI analysis', error as Error);
            return this.handleError(error);
        }
    }

    private generatePrompt(request: AIAnalysisRequest): string {
        return `
Analyze the following ${request.language} code for security vulnerabilities:

\`\`\`${request.language}
${request.code}
\`\`\`

${request.context ? `Additional context: ${request.context}\n` : ''}

Provide a detailed security analysis including:
1. Identified vulnerabilities with CWE IDs
2. Severity level (info/warning/error)
3. Line numbers where issues occur
4. Detailed description of each vulnerability
5. Specific remediation steps

Format the response as a JSON object with the following structure:
{
    "issues": [
        {
            "type": "vulnerability-type",
            "severity": "error|warning|info",
            "line": line-number,
            "column": column-number,
            "cwe": "CWE-XXX",
            "description": "detailed-description",
            "remediation": "specific-steps"
        }
    ],
    "confidence": 0.95,
    "suggestions": [
        "general-improvement-suggestions"
    ]
}`;
    }

    private parseResponse(response: string): AIAnalysisResponse {
        try {
            // Extract JSON from response
            const jsonMatch = response.match(/\{[\s\S]*\}/);
            if (!jsonMatch) {
                throw new Error('No valid JSON found in response');
            }

            const parsed = JSON.parse(jsonMatch[0]);
            
            // Validate and normalize the response
            return {
                issues: (parsed.issues || []).map((issue: any) => ({
                    type: issue.type || 'unknown',
                    severity: this.normalizeSeverity(issue.severity),
                    message: issue.description || 'Unknown issue',
                    line: parseInt(issue.line) || 0,
                    column: parseInt(issue.column) || 0,
                    cwe: issue.cwe,
                    description: issue.description || '',
                    remediation: issue.remediation || ''
                })),
                confidence: parsed.confidence || 0.5,
                suggestions: parsed.suggestions || []
            };
        } catch (error) {
            Logger.error('Error parsing AI response', error as Error);
            return {
                issues: [],
                confidence: 0,
                error: 'Failed to parse AI response'
            };
        }
    }

    private handleError(error: any): AIAnalysisResponse {
        const errorMessage = error.response?.data?.error?.message || error.message || 'Unknown error';
        
        if (error.response?.status === 429) {
            this.rateLimiter.handleRateLimit();
        }

        return {
            issues: [],
            confidence: 0,
            error: `AI analysis failed: ${errorMessage}`
        };
    }

    private normalizeSeverity(severity: string): 'info' | 'warning' | 'error' {
        severity = severity.toLowerCase();
        if (severity === 'high' || severity === 'critical' || severity === 'error') {
            return 'error';
        }
        if (severity === 'medium' || severity === 'moderate' || severity === 'warning') {
            return 'warning';
        }
        return 'info';
    }
}

class RateLimiter {
    private requestsPerMinute: number;
    private requestTimes: number[] = [];
    private backoffUntil: number = 0;

    constructor(requestsPerMinute: number) {
        this.requestsPerMinute = requestsPerMinute;
    }

    public async waitForAvailability(): Promise<void> {
        // Clean up old requests
        const now = Date.now();
        this.requestTimes = this.requestTimes.filter(time => now - time < 60000);

        // Check backoff
        if (now < this.backoffUntil) {
            throw new Error(`Rate limit exceeded. Please wait ${Math.ceil((this.backoffUntil - now) / 1000)} seconds.`);
        }

        // Check rate limit
        if (this.requestTimes.length >= this.requestsPerMinute) {
            const oldestRequest = this.requestTimes[0];
            const waitTime = 60000 - (now - oldestRequest);
            if (waitTime > 0) {
                await new Promise(resolve => setTimeout(resolve, waitTime));
            }
        }

        this.requestTimes.push(Date.now());
    }

    public hasRequests(): boolean {
        const now = Date.now();
        return now >= this.backoffUntil && 
               this.requestTimes.filter(time => now - time < 60000).length < this.requestsPerMinute;
    }

    public getRequestsRemaining(): number {
        const now = Date.now();
        if (now < this.backoffUntil) return 0;
        return this.requestsPerMinute - this.requestTimes.filter(time => now - time < 60000).length;
    }

    public handleRateLimit() {
        this.backoffUntil = Date.now() + 60000; // Back off for 1 minute
    }
}