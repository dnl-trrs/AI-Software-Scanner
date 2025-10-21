import * as vscode from 'vscode';
import { SecurityIssue } from '../../scanner';

export class SecurityCodeActionProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix,
        vscode.CodeActionKind.RefactorRewrite
    ];

    // Track diagnostic to security issue mapping
    private diagnosticMap = new Map<string, SecurityIssue>();

    // Update diagnostic mappings
    updateDiagnostics(filePath: string, issues: SecurityIssue[]) {
        issues.forEach(issue => {
            const key = `${filePath}:${issue.line}:${issue.column}`;
            this.diagnosticMap.set(key, issue);
        });
    }

    // Clear diagnostic mappings
    clearDiagnostics() {
        this.diagnosticMap.clear();
    }

    async provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext
    ): Promise<vscode.CodeAction[]> {
        const actions: vscode.CodeAction[] = [];

        // For each diagnostic in the range
        context.diagnostics.forEach(diagnostic => {
            const key = `${document.uri.fsPath}:${diagnostic.range.start.line}:${diagnostic.range.start.character}`;
            const issue = this.diagnosticMap.get(key);

            if (!issue) return;

            // Add quick fix based on issue type
            switch (issue.type) {
                case 'sql-injection':
                    actions.push(this.createParameterizedQueryFix(document, diagnostic, issue));
                    break;
                case 'xss':
                    actions.push(this.createSanitizeHtmlFix(document, diagnostic, issue));
                    break;
                case 'eval-usage':
                    actions.push(this.createEvalAlternativeFix(document, diagnostic, issue));
                    break;
                case 'insecure-random':
                    actions.push(this.createSecureRandomFix(document, diagnostic, issue));
                    break;
                case 'hardcoded-secret':
                    actions.push(this.createEnvironmentVariableFix(document, diagnostic, issue));
                    break;
            }

            // Always add an "Explain Issue" action
            actions.push(this.createExplainIssueAction(document, diagnostic, issue));
        });

        return actions;
    }

    private createParameterizedQueryFix(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        issue: SecurityIssue
    ): vscode.CodeAction {
        const fix = new vscode.CodeAction('Convert to parameterized query', vscode.CodeActionKind.QuickFix);
        fix.edit = new vscode.WorkspaceEdit();
        fix.edit.replace(
            document.uri,
            diagnostic.range,
            'const query = "SELECT * FROM users WHERE id = ?";\\nreturn db.query(query, [userId]);'
        );
        fix.isPreferred = true;
        return fix;
    }

    private createSanitizeHtmlFix(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        issue: SecurityIssue
    ): vscode.CodeAction {
        const fix = new vscode.CodeAction('Use safe DOM manipulation', vscode.CodeActionKind.QuickFix);
        fix.edit = new vscode.WorkspaceEdit();
        fix.edit.replace(
            document.uri,
            diagnostic.range,
            'element.textContent = input; // Safe alternative to innerHTML'
        );
        fix.isPreferred = true;
        return fix;
    }

    private createEvalAlternativeFix(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        issue: SecurityIssue
    ): vscode.CodeAction {
        const fix = new vscode.CodeAction('Replace eval with safer alternative', vscode.CodeActionKind.QuickFix);
        fix.edit = new vscode.WorkspaceEdit();
        fix.edit.replace(
            document.uri,
            diagnostic.range,
            'Function(code)() // Safer alternative to eval'
        );
        return fix;
    }

    private createSecureRandomFix(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        issue: SecurityIssue
    ): vscode.CodeAction {
        const fix = new vscode.CodeAction('Use cryptographically secure random', vscode.CodeActionKind.QuickFix);
        fix.edit = new vscode.WorkspaceEdit();
        fix.edit.replace(
            document.uri,
            diagnostic.range,
            'crypto.getRandomValues(new Uint8Array(8))'
        );
        fix.isPreferred = true;
        return fix;
    }

    private createEnvironmentVariableFix(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        issue: SecurityIssue
    ): vscode.CodeAction {
        const fix = new vscode.CodeAction('Move to environment variable', vscode.CodeActionKind.QuickFix);
        fix.edit = new vscode.WorkspaceEdit();
        fix.edit.replace(
            document.uri,
            diagnostic.range,
            'process.env.SECRET_KEY'
        );
        return fix;
    }

    private createExplainIssueAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        issue: SecurityIssue
    ): vscode.CodeAction {
        const action = new vscode.CodeAction('Explain Issue', vscode.CodeActionKind.QuickFix);
        action.command = {
            title: 'Explain Issue',
            command: 'aiSoftwareScanner.explainIssue',
            arguments: [issue]
        };
        return action;
    }
}