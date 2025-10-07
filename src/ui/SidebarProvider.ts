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

    public updateStats(stats: { recommendationsCount: number; issuesFixed: number; filesScanned: number; lastScan?: string }) {
        if (this._view) {
            this._view.webview.postMessage({ 
                type: 'updateStats', 
                stats: stats 
            });
        }
    }

    public showScanResults(results: any) {
        if (this._view) {
            this._view.webview.postMessage({ 
                type: 'scanResults', 
                results: results 
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
                        padding: 12px 24px;
                        margin-bottom: 12px;
                        background: var(--vscode-button-background);
                        color: var(--vscode-button-foreground);
                        border: none;
                        border-radius: 20px;
                        cursor: pointer;
                        font-size: 13px;
                        font-family: var(--vscode-font-family);
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        transition: all 0.2s ease;
                        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    }
                    
                    .action-button:hover {
                        background: var(--vscode-button-hoverBackground);
                        transform: translateY(-1px);
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
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
                        padding: 16px 20px;
                        background: var(--vscode-editor-background);
                        margin: 0 20px 20px;
                        border-radius: 8px;
                        border-left: 3px solid #007ACC;
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                    }
                    
                    .recommendations-count {
                        font-size: 28px;
                        font-weight: bold;
                        color: var(--vscode-foreground);
                    }
                    
                    .recommendations-label {
                        font-size: 13px;
                        color: var(--vscode-descriptionForeground);
                        margin-left: 12px;
                    }
                    
                    .stats-section {
                        padding: 16px 20px;
                        border-top: 1px solid var(--vscode-widget-border);
                    }
                    
                    .stats-item {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 8px 0;
                        font-size: 12px;
                    }
                    
                    .stats-label {
                        color: var(--vscode-descriptionForeground);
                    }
                    
                    .stats-value {
                        font-weight: 600;
                        color: var(--vscode-foreground);
                    }
                    
                    .scan-results {
                        padding: 16px 20px;
                        background: var(--vscode-editor-background);
                        margin: 16px;
                        border-radius: 6px;
                        border: 1px solid var(--vscode-widget-border);
                        max-height: 200px;
                        overflow-y: auto;
                        display: none;
                    }
                    
                    .scan-results.active {
                        display: block;
                    }
                    
                    .scan-results-title {
                        font-size: 13px;
                        font-weight: 600;
                        margin-bottom: 12px;
                        color: var(--vscode-foreground);
                    }
                    
                    .scan-item {
                        padding: 6px 0;
                        font-size: 12px;
                        color: var(--vscode-descriptionForeground);
                        border-bottom: 1px solid var(--vscode-widget-border);
                    }
                    
                    .scan-item:last-child {
                        border-bottom: none;
                    }
                    
                    .severity-indicator {
                        display: inline-block;
                        width: 8px;
                        height: 8px;
                        border-radius: 50%;
                        margin-right: 6px;
                    }
                    
                    .severity-critical { background: #ff0000; }
                    .severity-high { background: #ff8800; }
                    .severity-medium { background: #ffcc00; }
                    .severity-low { background: #0099ff; }
                </style>
            </head>
            <body>
                <div class="header">
                    <div class="title">AI Software Scanner</div>
                    <div class="subtitle">Scan your code with A.I. to get security recommendations</div>
                </div>
                
                <div class="recommendations-info">
                    <div style="display: flex; align-items: baseline;">
                        <div class="recommendations-count" id="recommendationsCount">0</div>
                        <div class="recommendations-label">Recommendations Found</div>
                    </div>
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
                        View All Recommendations
                    </button>
                </div>
                
                <div class="stats-section">
                    <div class="stats-item">
                        <span class="stats-label">Last Scan</span>
                        <span class="stats-value" id="lastScan">Not yet scanned</span>
                    </div>
                    <div class="stats-item">
                        <span class="stats-label">Files Scanned</span>
                        <span class="stats-value" id="filesScanned">0</span>
                    </div>
                    <div class="stats-item">
                        <span class="stats-label">Issues Fixed</span>
                        <span class="stats-value" id="issuesFixed">0</span>
                    </div>
                </div>
                
                <div class="scan-results" id="scanResults">
                    <div class="scan-results-title">Scan Results</div>
                    <div id="scanResultsList"></div>
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
                    
                    // Handle messages from extension
                    window.addEventListener('message', event => {
                        const message = event.data;
                        switch (message.type) {
                            case 'updateCount':
                                document.getElementById('recommendationsCount').textContent = message.value;
                                break;
                            case 'updateStats':
                                if (message.stats) {
                                    document.getElementById('recommendationsCount').textContent = message.stats.recommendationsCount;
                                    document.getElementById('filesScanned').textContent = message.stats.filesScanned;
                                    document.getElementById('issuesFixed').textContent = message.stats.issuesFixed;
                                    if (message.stats.lastScan) {
                                        document.getElementById('lastScan').textContent = message.stats.lastScan;
                                    }
                                }
                                break;
                            case 'scanResults':
                                const resultsDiv = document.getElementById('scanResults');
                                const resultsList = document.getElementById('scanResultsList');
                                if (message.results && message.results.length > 0) {
                                    resultsList.innerHTML = message.results.map(item => 
                                        '<div class="scan-item">' +
                                            '<span class="severity-indicator severity-' + item.severity + '"></span>' +
                                            '<strong>' + item.type + ':</strong> Line ' + item.line + ' - ' + item.message +
                                        '</div>'
                                    ).join('');
                                    resultsDiv.classList.add('active');
                                } else {
                                    resultsDiv.classList.remove('active');
                                }
                                break;
                        }
                    });
                </script>
            </body>
            </html>`;
    }
}