import * as vscode from 'vscode';
import { SecurityIssue } from '../../scanner';

export class IssueExplainer {
    private static readonly CWE_BASE_URL = 'https://cwe.mitre.org/data/definitions/';

    async explainIssue(issue: SecurityIssue) {
        const panel = vscode.window.createWebviewPanel(
            'securityIssueExplanation',
            'Security Issue Explanation',
            vscode.ViewColumn.Beside,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );

        panel.webview.html = await this.generateExplanationHtml(issue);
    }

    private async generateExplanationHtml(issue: SecurityIssue): Promise<string> {
        const cweLink = issue.cwe 
            ? `${IssueExplainer.CWE_BASE_URL}${issue.cwe.replace('CWE-', '')}.html`
            : undefined;

        return `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {
                        padding: 20px;
                        line-height: 1.6;
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
                    }
                    .severity {
                        display: inline-block;
                        padding: 4px 8px;
                        border-radius: 4px;
                        font-weight: bold;
                        margin-bottom: 16px;
                    }
                    .severity-error { background-color: #ff000020; color: #d73a49; }
                    .severity-warning { background-color: #ffd70020; color: #e36209; }
                    .severity-info { background-color: #0366d620; color: #0366d6; }
                    .section {
                        margin-bottom: 24px;
                    }
                    .section h2 {
                        margin-bottom: 8px;
                        color: #24292e;
                    }
                    pre {
                        background-color: #f6f8fa;
                        padding: 16px;
                        border-radius: 6px;
                        overflow-x: auto;
                    }
                    .link {
                        color: #0366d6;
                        text-decoration: none;
                    }
                    .link:hover {
                        text-decoration: underline;
                    }
                </style>
            </head>
            <body>
                <h1>${this.escapeHtml(issue.type)}</h1>
                
                <div class="severity severity-${issue.severity}">
                    ${issue.severity.toUpperCase()}
                </div>

                <div class="section">
                    <h2>Description</h2>
                    <p>${this.escapeHtml(issue.description || issue.message)}</p>
                </div>

                ${issue.remediation ? `
                <div class="section">
                    <h2>Remediation</h2>
                    <p>${this.escapeHtml(issue.remediation)}</p>
                </div>
                ` : ''}

                ${cweLink ? `
                <div class="section">
                    <h2>Reference</h2>
                    <p>
                        <a class="link" href="${cweLink}" target="_blank">
                            ${issue.cwe} - View in CWE Database
                        </a>
                    </p>
                </div>
                ` : ''}

                <div class="section">
                    <h2>Location</h2>
                    <p>Line ${issue.line}, Column ${issue.column}</p>
                </div>

                ${this.getExampleCode(issue)}
            </body>
            </html>
        `;
    }

    private getExampleCode(issue: SecurityIssue): string {
        const examples: { [key: string]: string } = {
            'sql-injection': `
                // Vulnerable Code:
                const query = \`SELECT * FROM users WHERE id = \${userId}\`;

                // Secure Code:
                const query = "SELECT * FROM users WHERE id = ?";
                db.query(query, [userId]);
            `,
            'xss': `
                // Vulnerable Code:
                element.innerHTML = userInput;

                // Secure Code:
                element.textContent = userInput;
                // Or use a sanitization library:
                element.innerHTML = DOMPurify.sanitize(userInput);
            `,
            'hardcoded-secret': `
                // Vulnerable Code:
                const apiKey = "1234567890abcdef";

                // Secure Code:
                const apiKey = process.env.API_KEY;
            `,
            'insecure-random': `
                // Vulnerable Code:
                const token = Math.random().toString(36);

                // Secure Code:
                const token = crypto.randomBytes(32).toString('hex');
            `
        };

        const example = examples[issue.type];
        if (!example) return '';

        return `
            <div class="section">
                <h2>Code Examples</h2>
                <pre><code>${this.escapeHtml(example)}</code></pre>
            </div>
        `;
    }

    private escapeHtml(unsafe: string): string {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
}