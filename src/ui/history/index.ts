import * as vscode from 'vscode';
import { SecurityIssue } from '../../scanner';

interface ScanResult {
    timestamp: number;
    issues: { [filePath: string]: SecurityIssue[] };
    totalIssues: number;
}

export class ScanHistoryManager {
    private static readonly MAX_HISTORY = 10;
    private history: ScanResult[] = [];

    // Add new scan result to history
    addScanResult(issues: { [filePath: string]: SecurityIssue[] }) {
        const totalIssues = Object.values(issues).reduce((sum, fileIssues) => sum + fileIssues.length, 0);
        
        const scanResult: ScanResult = {
            timestamp: Date.now(),
            issues,
            totalIssues
        };

        this.history.unshift(scanResult);

        // Keep only the last MAX_HISTORY entries
        if (this.history.length > ScanHistoryManager.MAX_HISTORY) {
            this.history = this.history.slice(0, ScanHistoryManager.MAX_HISTORY);
        }
    }

    // Get scan history
    getHistory(): ScanResult[] {
        return this.history;
    }

    // Compare two scan results
    compareScanResults(baseIndex: number, compareIndex: number): string {
        if (baseIndex >= this.history.length || compareIndex >= this.history.length) {
            throw new Error('Invalid scan indices');
        }

        const base = this.history[baseIndex];
        const compare = this.history[compareIndex];

        let report = `# Scan Comparison Report\n\n`;
        report += `Base scan: ${new Date(base.timestamp).toLocaleString()}\n`;
        report += `Compare scan: ${new Date(compare.timestamp).toLocaleString()}\n\n`;

        const allFiles = new Set([
            ...Object.keys(base.issues),
            ...Object.keys(compare.issues)
        ]);

        let newIssues = 0;
        let resolvedIssues = 0;
        let unchangedIssues = 0;

        allFiles.forEach(file => {
            const baseIssues = base.issues[file] || [];
            const compareIssues = compare.issues[file] || [];

            // Find new and resolved issues
            const newFileIssues = compareIssues.filter(issue => 
                !baseIssues.some(baseIssue => 
                    this.isSameIssue(baseIssue, issue)
                )
            );

            const resolvedFileIssues = baseIssues.filter(issue => 
                !compareIssues.some(compareIssue => 
                    this.isSameIssue(compareIssue, issue)
                )
            );

            if (newFileIssues.length > 0 || resolvedFileIssues.length > 0) {
                report += `\n## ${file}\n`;
                
                if (newFileIssues.length > 0) {
                    report += '\n### New Issues:\n';
                    newFileIssues.forEach(issue => {
                        report += `- [${issue.severity.toUpperCase()}] ${issue.message} (line ${issue.line})\n`;
                    });
                    newIssues += newFileIssues.length;
                }

                if (resolvedFileIssues.length > 0) {
                    report += '\n### Resolved Issues:\n';
                    resolvedFileIssues.forEach(issue => {
                        report += `- [${issue.severity.toUpperCase()}] ${issue.message} (line ${issue.line})\n`;
                    });
                    resolvedIssues += resolvedFileIssues.length;
                }
            }

            // Count unchanged issues
            unchangedIssues += compareIssues.filter(issue => 
                baseIssues.some(baseIssue => 
                    this.isSameIssue(baseIssue, issue)
                )
            ).length;
        });

        report += `\n## Summary\n`;
        report += `- New issues: ${newIssues}\n`;
        report += `- Resolved issues: ${resolvedIssues}\n`;
        report += `- Unchanged issues: ${unchangedIssues}\n`;
        report += `- Total issues in new scan: ${compare.totalIssues}\n`;

        return report;
    }

    private isSameIssue(a: SecurityIssue, b: SecurityIssue): boolean {
        return a.type === b.type && 
               a.line === b.line && 
               a.column === b.column && 
               a.message === b.message;
    }

    // Clear history
    clearHistory() {
        this.history = [];
    }
}