import * as vscode from 'vscode';
import { SecurityIssue } from '../../scanner';

export class DiagnosticsManager {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('aiSoftwareScanner');
    }

    updateDiagnostics(filePath: string, issues: SecurityIssue[]): void {
        const uri = vscode.Uri.file(filePath);
        const diagnostics: vscode.Diagnostic[] = issues.map(issue => {
            const range = new vscode.Range(
                issue.line - 1,
                issue.column || 0,
                issue.endLine ? issue.endLine - 1 : issue.line - 1,
                issue.endColumn || Number.MAX_VALUE
            );

            const diagnostic = new vscode.Diagnostic(
                range,
                issue.message,
                this.getSeverity(issue.severity)
            );

            diagnostic.code = issue.cwe || issue.type;
            diagnostic.source = 'AI Software Scanner';
            diagnostic.relatedInformation = [];

            if (issue.description) {
                diagnostic.relatedInformation.push(
                    new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(uri, range),
                        issue.description
                    )
                );
            }

            if (issue.remediation) {
                diagnostic.relatedInformation.push(
                    new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(uri, range),
                        `Remediation: ${issue.remediation}`
                    )
                );
            }

            return diagnostic;
        });

        this.diagnosticCollection.set(uri, diagnostics);
    }

    clearDiagnostics(filePath?: string): void {
        if (filePath) {
            this.diagnosticCollection.delete(vscode.Uri.file(filePath));
        } else {
            this.diagnosticCollection.clear();
        }
    }

    private getSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity.toLowerCase()) {
            case 'error':
                return vscode.DiagnosticSeverity.Error;
            case 'warning':
                return vscode.DiagnosticSeverity.Warning;
            case 'info':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}