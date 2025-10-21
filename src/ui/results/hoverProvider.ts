import * as vscode from 'vscode';
import { SecurityIssue } from '../../scanner';

export class SecurityHoverProvider implements vscode.HoverProvider {
    private issues: Map<string, SecurityIssue[]> = new Map();

    updateIssues(filePath: string, newIssues: SecurityIssue[]): void {
        this.issues.set(filePath, newIssues);
    }

    clearIssues(filePath?: string): void {
        if (filePath) {
            this.issues.delete(filePath);
        } else {
            this.issues.clear();
        }
    }

    provideHover(
        document: vscode.TextDocument,
        position: vscode.Position
    ): vscode.ProviderResult<vscode.Hover> {
        const issues = this.issues.get(document.uri.fsPath);
        if (!issues) {
            return null;
        }

        // Find issues that overlap with the current position
        const issuesAtPosition = issues.filter(issue => {
            const startLine = issue.line - 1;
            const endLine = issue.endLine ? issue.endLine - 1 : startLine;
            const startColumn = issue.column || 0;
            const endColumn = issue.endColumn || Number.MAX_VALUE;

            return position.line >= startLine &&
                   position.line <= endLine &&
                   (position.line !== startLine || position.character >= startColumn) &&
                   (position.line !== endLine || position.character <= endColumn);
        });

        if (issuesAtPosition.length === 0) {
            return null;
        }

        const hoverContent: vscode.MarkdownString[] = issuesAtPosition.map(issue => {
            const markdown = new vscode.MarkdownString();
            markdown.isTrusted = true;
            markdown.supportHtml = true;

            const severityIcon = this.getSeverityIcon(issue.severity);
            markdown.appendMarkdown(`${severityIcon} **${issue.type}**\n\n`);
            markdown.appendMarkdown(`${issue.message}\n\n`);

            if (issue.cwe) {
                markdown.appendMarkdown(`**CWE:** [${issue.cwe}](https://cwe.mitre.org/data/definitions/${issue.cwe.replace('CWE-', '')}.html)\n\n`);
            }

            if (issue.description) {
                markdown.appendMarkdown(`**Description:**\n${issue.description}\n\n`);
            }

            if (issue.remediation) {
                markdown.appendMarkdown(`**Remediation:**\n${issue.remediation}\n`);
            }

            return markdown;
        });

        return new vscode.Hover(hoverContent);
    }

    private getSeverityIcon(severity: string): string {
        switch (severity.toLowerCase()) {
            case 'error':
                return '$(error) ';
            case 'warning':
                return '$(warning) ';
            default:
                return '$(info) ';
        }
    }
}