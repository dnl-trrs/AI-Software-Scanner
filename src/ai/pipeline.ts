/**
 * Code Analysis Pipeline Module
 * Handles preprocessing, context analysis, and result standardization
 */

import * as vscode from 'vscode';
import { AIAnalysisResponse } from './services/base';

interface CodeContext {
    imports: string[];
    dependencies: string[];
    framework?: string;
    projectType?: string;
    fileType: string;
    relatedFiles?: string[];
}

interface ProcessedCode {
    code: string;
    segments: CodeSegment[];
    context: CodeContext;
}

interface CodeSegment {
    code: string;
    startLine: number;
    endLine: number;
    type: 'import' | 'class' | 'function' | 'variable' | 'other';
}

export class AnalysisPipeline {
    /**
     * Processes code for AI analysis
     */
    static async preprocessCode(document: vscode.TextDocument): Promise<ProcessedCode> {
        const code = document.getText();
        const segments = await this.segmentCode(document);
        const context = await this.analyzeContext(document);

        return {
            code: this.cleanCode(code),
            segments,
            context
        };
    }

    /**
     * Segments code into logical parts for focused analysis
     */
    private static async segmentCode(document: vscode.TextDocument): Promise<CodeSegment[]> {
        const segments: CodeSegment[] = [];
        const text = document.getText();
        const lines = text.split('\n');

        let currentSegment: Partial<CodeSegment> = {};
        let inComment = false;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();

            // Handle multi-line comments
            if (line.includes('/*')) inComment = true;
            if (line.includes('*/')) inComment = false;
            if (inComment) continue;

            // Skip single-line comments and empty lines
            if (line.startsWith('//') || line === '') continue;

            // Detect segment types
            if (line.match(/^import\s|^from\s.*import/)) {
                this.finalizeSegment(currentSegment, segments, i);
                currentSegment = { type: 'import', startLine: i };
            } else if (line.match(/^(class|interface|enum)\s/)) {
                this.finalizeSegment(currentSegment, segments, i);
                currentSegment = { type: 'class', startLine: i };
            } else if (line.match(/^(function|async|public|private|protected).*\(/)) {
                this.finalizeSegment(currentSegment, segments, i);
                currentSegment = { type: 'function', startLine: i };
            } else if (line.match(/^(const|let|var)\s/)) {
                this.finalizeSegment(currentSegment, segments, i);
                currentSegment = { type: 'variable', startLine: i };
            }

            // Check for segment end
            if (line === '}' && currentSegment.startLine !== undefined) {
                this.finalizeSegment(currentSegment, segments, i);
                currentSegment = {};
            }
        }

        // Add final segment if exists
        if (currentSegment.startLine !== undefined) {
            this.finalizeSegment(currentSegment, segments, lines.length - 1);
        }

        return segments;
    }

    /**
     * Analyzes the context of the code
     */
    private static async analyzeContext(document: vscode.TextDocument): Promise<CodeContext> {
        const workspace = vscode.workspace.getWorkspaceFolder(document.uri);
        const context: CodeContext = {
            imports: [],
            dependencies: [],
            fileType: document.languageId
        };

        // Extract imports
        const text = document.getText();
        const importRegex = /^import\s+.*|^from\s+.*import/gm;
        const imports = text.match(importRegex) || [];
        context.imports = imports.map(imp => imp.trim());

        if (workspace) {
            try {
                // Try to find package.json or similar dependency files
                const packageJson = await vscode.workspace.findFiles('**/package.json', '**/node_modules/**');
                if (packageJson.length > 0) {
                    const content = await vscode.workspace.fs.readFile(packageJson[0]);
                    const pkg = JSON.parse(content.toString());
                    context.dependencies = [
                        ...Object.keys(pkg.dependencies || {}),
                        ...Object.keys(pkg.devDependencies || {})
                    ];
                    context.projectType = 'node';
                }

                // Check for common framework indicators
                if (context.dependencies.includes('react')) {
                    context.framework = 'react';
                } else if (context.dependencies.includes('@angular/core')) {
                    context.framework = 'angular';
                } else if (context.dependencies.includes('vue')) {
                    context.framework = 'vue';
                }

                // Find related files
                const fileName = document.fileName;
                const extension = fileName.split('.').pop() || '';
                const baseName = fileName.slice(0, -extension.length - 1);
                const relatedPatterns = [
                    `${baseName}.*`,
                    `${baseName.replace(/\..*$/, '')}.*`
                ];

                const relatedFiles = await Promise.all(
                    relatedPatterns.map(pattern =>
                        vscode.workspace.findFiles(pattern, '**/node_modules/**')
                    )
                );

                context.relatedFiles = relatedFiles
                    .flat()
                    .map(file => file.fsPath)
                    .filter(path => path !== document.fileName);

            } catch (error) {
                console.error('Error analyzing context:', error);
            }
        }

        return context;
    }

    /**
     * Cleans and normalizes code for AI analysis
     */
    private static cleanCode(code: string): string {
        return code
            .replace(/\/\*[\s\S]*?\*\//g, '') // Remove multi-line comments
            .replace(/\/\/.*/g, '') // Remove single-line comments
            .replace(/\n\s*\n\s*\n/g, '\n\n') // Normalize whitespace
            .trim();
    }

    /**
     * Finalizes a code segment and adds it to the segments array
     */
    private static finalizeSegment(
        currentSegment: Partial<CodeSegment>,
        segments: CodeSegment[],
        endLine: number
    ) {
        if (currentSegment.startLine !== undefined) {
            segments.push({
                type: currentSegment.type || 'other',
                startLine: currentSegment.startLine,
                endLine,
                code: ''  // Will be filled later if needed
            });
        }
    }

    /**
     * Processes AI analysis results and standardizes them
     */
    static processResults(
        results: AIAnalysisResponse,
        processed: ProcessedCode
    ): AIAnalysisResponse {
        // Adjust confidence based on context matches
        let confidenceScore = results.confidence;

        // Adjust confidence based on framework detection
        if (processed.context.framework && results.issues.some(i => 
            i.message.toLowerCase().includes(processed.context.framework!.toLowerCase()))) {
            confidenceScore *= 1.2;
        }

        // Adjust confidence based on import analysis
        const importMatches = results.issues.filter(issue => 
            processed.context.imports.some(imp => 
                issue.message.toLowerCase().includes(imp.toLowerCase())
            )
        ).length;
        if (importMatches > 0) {
            confidenceScore *= 1 + (importMatches * 0.1);
        }

        // Cap confidence at 1.0
        confidenceScore = Math.min(confidenceScore, 1.0);

        // Enhance issue descriptions with context
        const enhancedIssues = results.issues.map(issue => {
            // Add framework-specific context if available
            if (processed.context.framework) {
                issue.description += `\nFramework Context: This issue is particularly important in ${processed.context.framework} applications.`;
            }

            // Add dependency-related context
            const relatedDeps = processed.context.dependencies.filter(dep =>
                issue.message.toLowerCase().includes(dep.toLowerCase())
            );
            if (relatedDeps.length > 0) {
                issue.description += `\nRelated Dependencies: ${relatedDeps.join(', ')}`;
            }

            return issue;
        });

        return {
            ...results,
            issues: enhancedIssues,
            confidence: confidenceScore
        };
    }
}