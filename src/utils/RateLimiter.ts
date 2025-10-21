import * as crypto from 'crypto';

/**
 * Rate limiter to prevent API rate limit errors
 */
export class RateLimiter {
    private lastRequestTime = 0;
    private requestCount = 0;
    private readonly maxRequestsPerMinute: number;
    private readonly minDelayMs: number;
    
    constructor(maxRequestsPerMinute: number = 20, minDelayMs: number = 1000) {
        this.maxRequestsPerMinute = maxRequestsPerMinute;
        this.minDelayMs = minDelayMs;
    }
    
    /**
     * Wait if necessary to respect rate limits
     */
    async waitIfNeeded(): Promise<void> {
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequestTime;
        
        // Reset counter every minute
        if (timeSinceLastRequest > 60000) {
            this.requestCount = 0;
        }
        
        // Check if we've hit the rate limit
        if (this.requestCount >= this.maxRequestsPerMinute) {
            const waitTime = 60000 - timeSinceLastRequest;
            console.log(`Rate limit reached. Waiting ${waitTime}ms...`);
            await this.delay(waitTime);
            this.requestCount = 0;
        }
        
        // Enforce minimum delay between requests
        if (this.lastRequestTime > 0 && timeSinceLastRequest < this.minDelayMs) {
            const waitTime = this.minDelayMs - timeSinceLastRequest;
            await this.delay(waitTime);
        }
        
        this.lastRequestTime = Date.now();
        this.requestCount++;
    }
    
    private delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

/**
 * Cache interface for scan results
 */
export interface CachedResult<T> {
    data: T;
    timestamp: number;
    hash: string;
}

/**
 * Simple cache implementation for scan results
 */
export class ScanCache<T> {
    private cache = new Map<string, CachedResult<T>>();
    private readonly cacheDuration: number;
    
    constructor(cacheDurationMs: number = 3600000) { // 1 hour default
        this.cacheDuration = cacheDurationMs;
    }
    
    /**
     * Generate hash from content
     */
    private generateHash(content: string): string {
        return crypto.createHash('sha256').update(content).digest('hex');
    }
    
    /**
     * Get cached result if valid
     */
    get(content: string): T | null {
        const hash = this.generateHash(content);
        const cached = this.cache.get(hash);
        
        if (cached && (Date.now() - cached.timestamp < this.cacheDuration)) {
            console.log('Cache hit for content hash:', hash.substring(0, 8));
            return cached.data;
        }
        
        return null;
    }
    
    /**
     * Store result in cache
     */
    set(content: string, data: T): void {
        const hash = this.generateHash(content);
        this.cache.set(hash, {
            data,
            timestamp: Date.now(),
            hash
        });
        console.log('Cached result with hash:', hash.substring(0, 8));
    }
    
    /**
     * Clear expired entries
     */
    cleanUp(): void {
        const now = Date.now();
        for (const [key, value] of this.cache.entries()) {
            if (now - value.timestamp > this.cacheDuration) {
                this.cache.delete(key);
            }
        }
    }
    
    /**
     * Clear all cache
     */
    clear(): void {
        this.cache.clear();
    }
}

/**
 * Code chunking utility for large files
 */
export class CodeChunker {
    private readonly maxTokens: number;
    private readonly charsPerToken: number;
    
    constructor(maxTokens: number = 2000, charsPerToken: number = 4) {
        this.maxTokens = maxTokens;
        this.charsPerToken = charsPerToken;
    }
    
    /**
     * Split code into manageable chunks
     */
    splitIntoChunks(code: string): string[] {
        const maxChars = this.maxTokens * this.charsPerToken;
        
        if (code.length <= maxChars) {
            return [code];
        }
        
        const chunks: string[] = [];
        const lines = code.split('\n');
        let currentChunk = '';
        let currentLineNumber = 1;
        const lineNumbers: { start: number; end: number }[] = [];
        
        for (const line of lines) {
            if ((currentChunk + line + '\n').length > maxChars && currentChunk.length > 0) {
                // Save current chunk
                chunks.push(currentChunk);
                currentChunk = line + '\n';
            } else {
                currentChunk += line + '\n';
            }
            currentLineNumber++;
        }
        
        // Add the last chunk
        if (currentChunk.trim()) {
            chunks.push(currentChunk);
        }
        
        console.log(`Split code into ${chunks.length} chunks`);
        return chunks;
    }
    
    /**
     * Estimate token count for a string
     */
    estimateTokens(text: string): number {
        return Math.ceil(text.length / this.charsPerToken);
    }
}