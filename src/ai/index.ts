/**
 * AI Integration Module
 * 
 * This module will handle AI-powered code analysis including:
 * - Integration with AI services (OpenAI, etc.)
 * - Code analysis and vulnerability detection
 * - Generating security recommendations
 */

import { AIService, AIServiceConfig, AIAnalysisRequest } from './services/base';
import { OpenAIService } from './services/openai';

export type { AIAnalysisRequest, AIAnalysisResponse, AISecurityIssue } from './services/base';
export { AIService, AIServiceConfig } from './services/base';
export { OpenAIService } from './services/openai';

export type AIProvider = 'openai' | 'anthropic' | 'local';

export interface AIManagerConfig extends AIServiceConfig {
    provider: AIProvider;
    fallbackProvider?: AIProvider;
}

export class AIManager {
    private service: AIService;
    private fallbackService?: AIService;
    /* @ts-expect-error Used in constructor */
    private readonly config: AIManagerConfig;

    constructor(config: AIManagerConfig) {
        this.config = config;
        this.service = this.createService(config.provider, config);
        
        if (config.fallbackProvider) {
            this.fallbackService = this.createService(config.fallbackProvider, config);
        }
    }

    private createService(provider: AIProvider, config: AIServiceConfig): AIService {
        switch (provider) {
            case 'openai':
                return new OpenAIService(config);
            case 'anthropic':
                throw new Error('Anthropic support not yet implemented');
            case 'local':
                throw new Error('Local model support not yet implemented');
            default:
                throw new Error(`Unsupported AI provider: ${provider}`);
        }
    }

    public async analyze(code: string, language: string, context?: string) {
        // Try primary service
        try {
            if (this.service.isReady()) {
                const request: AIAnalysisRequest = {
                    code,
                    language,
                    ...(context && { context })
                };
                return await this.service.analyze(request);
            }
        } catch (error) {
            console.error('Primary AI service failed:', error);
        }

        // Try fallback service if available
        if (this.fallbackService?.isReady()) {
            try {
                const request: AIAnalysisRequest = {
                    code,
                    language,
                    ...(context && { context })
                };
                return await this.fallbackService.analyze(request);
            } catch (error) {
                console.error('Fallback AI service failed:', error);
            }
        }

        throw new Error('All AI services failed or unavailable');
    }

    public isReady(): boolean {
        return this.service.isReady() || (this.fallbackService?.isReady() ?? false);
    }

    public getRequestsRemaining(): number {
        return this.service.getRequestsRemaining() + (this.fallbackService?.getRequestsRemaining() ?? 0);
    }
}