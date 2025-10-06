import * as vscode from 'vscode';

export class SidebarProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'aiScanner.sidebar';

    private _view?: vscode.WebviewView;

    constructor(
        private readonly _extensionUri: vscode.Uri,
        private _context: vscode.ExtensionContext
    ) {}

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri]
        };

        webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

        // Handle messages from the webview
        webviewView.webview.onDidReceiveMessage(data => {
            switch (data.type) {
                case 'scanFile':
                    vscode.commands.executeCommand('ai-software-scanner.scanFile');
                    break;
                case 'viewRecommendations':
                    vscode.commands.executeCommand('ai-software-scanner.showRecommendations');
                    break;
                case 'manageSubscription':
                    vscode.commands.executeCommand('ai-software-scanner.manageSubscription');
                    break;
            }
        });
    }

    public updateRecommendations(count: number) {
        if (this._view) {
            this._view.webview.postMessage({ 
                type: 'updateCount', 
                value: count 
            });
        }
    }

    private _getHtmlForWebview(webview: vscode.Webview) {
        const styleResetUri = webview.asWebviewUri(
            vscode.Uri.joinPath(this._extensionUri, 'media', 'reset.css')
        );
        const styleVSCodeUri = webview.asWebviewUri(
            vscode.Uri.joinPath(this._extensionUri, 'media', 'vscode.css')
        );

        return `<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>AI Software Scanner</title>
                <style>
                    body {
                        padding: 0;
                        margin: 0;
                        background: var(--vscode-sideBar-background);
                    }
                    
                    .header {
                        padding: 20px;
                        border-bottom: 1px solid var(--vscode-widget-border);
                    }
                    
                    .title {
                        font-size: 14px;
                        font-weight: 600;
                        color: var(--vscode-foreground);
                        margin-bottom: 8px;
                    }
                    
                    .subtitle {
                        font-size: 11px;
                        color: var(--vscode-descriptionForeground);
                        line-height: 1.4;
                    }
                    
                    .actions {
                        padding: 20px;
                    }
                    
                    .action-button {
                        width: 100%;
                        padding: 10px 16px;
                        margin-bottom: 12px;
                        background: var(--vscode-button-background);
                        color: var(--vscode-button-foreground);
                        border: none;
                        border-radius: 2px;
                        cursor: pointer;
                        font-size: 13px;
                        font-family: var(--vscode-font-family);
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        transition: background-color 0.2s;
                    }
                    
                    .action-button:hover {
                        background: var(--vscode-button-hoverBackground);
                    }
                    
                    .action-button.primary {
                        background: #0E639C;
                        color: white;
                    }
                    
                    .action-button.primary:hover {
                        background: #1177BB;
                    }
                    
                    .action-button .icon {
                        margin-right: 8px;
                    }
                    
                    .scan-progress {
                        display: none;
                        text-align: center;
                        padding: 12px;
                        color: var(--vscode-foreground);
                        font-size: 12px;
                    }
                    
                    .scan-progress.active {
                        display: block;
                    }
                    
                    .progress-bar {
                        width: 100%;
                        height: 3px;
                        background: var(--vscode-progressBar-background);
                        margin-top: 8px;
                        border-radius: 2px;
                        overflow: hidden;
                    }
                    
                    .progress-fill {
                        height: 100%;
                        background: var(--vscode-progressBar-foreground);
                        width: 0;
                        transition: width 0.3s;
                    }
                    
                    .recommendations-info {
                        padding: 20px;
                        background: var(--vscode-editor-background);
                        margin: 0 20px 20px;
                        border-radius: 4px;
                        border-left: 3px solid #007ACC;
                    }
                    
                    .recommendations-count {
                        font-size: 24px;
                        font-weight: bold;
                        color: var(--vscode-foreground);
                        margin-bottom: 4px;
                    }
                    
                    .recommendations-label {
                        font-size: 12px;
                        color: var(--vscode-descriptionForeground);
                    }
                    
                    .divider {
                        height: 1px;
                        background: var(--vscode-widget-border);
                        margin: 20px 0;
                    }
                    
                    .subscription-status {
                        padding: 12px 20px;
                        font-size: 11px;
                        color: var(--vscode-descriptionForeground);
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                    }
                    
                    .status-badge {
                        padding: 2px 8px;
                        background: var(--vscode-badge-background);
                        color: var(--vscode-badge-foreground);
                        border-radius: 10px;
                        font-size: 10px;
                    }
                </style>
            </head>
            <body>
                <div class="header">
                    <div class="title">AI Software Scanner</div>
                    <div class="subtitle">Scan your code with A.I. to get security recommendations</div>
                </div>
                
                <div class="recommendations-info">
                    <div class="recommendations-count" id="recommendationsCount">0</div>
                    <div class="recommendations-label">All Recommendations</div>
                </div>
                
                <div class="actions">
                    <button class="action-button primary" id="scanFile">
                        <span class="icon">🔍</span>
                        Scan File
                    </button>
                    
                    <div class="scan-progress" id="scanProgress">
                        <span>Scanning...</span>
                        <div class="progress-bar">
                            <div class="progress-fill" id="progressFill"></div>
                        </div>
                    </div>
                    
                    <button class="action-button" id="viewRecommendations">
                        <span class="icon">📋</span>
                        View Recommendations
                    </button>
                    
                    <button class="action-button" id="manageSubscription">
                        <span class="icon">⚙️</span>
                        Manage Subscription
                    </button>
                </div>
                
                <div class="divider"></div>
                
                <div class="subscription-status">
                    <span>Subscription Status</span>
                    <span class="status-badge">FREE TRIAL</span>
                </div>
                
                <script>
                    const vscode = acquireVsCodeApi();
                    
                    document.getElementById('scanFile').addEventListener('click', () => {
                        vscode.postMessage({ type: 'scanFile' });
                        
                        // Show progress
                        const progress = document.getElementById('scanProgress');
                        const progressFill = document.getElementById('progressFill');
                        progress.classList.add('active');
                        
                        // Simulate progress
                        let width = 0;
                        const interval = setInterval(() => {
                            width += 10;
                            progressFill.style.width = width + '%';
                            if (width >= 100) {
                                clearInterval(interval);
                                setTimeout(() => {
                                    progress.classList.remove('active');
                                    progressFill.style.width = '0%';
                                }, 500);
                            }
                        }, 200);
                    });
                    
                    document.getElementById('viewRecommendations').addEventListener('click', () => {
                        vscode.postMessage({ type: 'viewRecommendations' });
                    });
                    
                    document.getElementById('manageSubscription').addEventListener('click', () => {
                        vscode.postMessage({ type: 'manageSubscription' });
                    });
                    
                    // Handle messages from extension
                    window.addEventListener('message', event => {
                        const message = event.data;
                        switch (message.type) {
                            case 'updateCount':
                                document.getElementById('recommendationsCount').textContent = message.value;
                                break;
                        }
                    });
                </script>
            </body>
            </html>`;
    }
}