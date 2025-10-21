// The module 'vscode' contains the VS Code extensibility API
import * as vscode from 'vscode';
import { Logger } from './utils';
import { CodeScanner, ScanOptions, SecurityIssue } from './scanner';

// Global extension state
let statusBarItem: vscode.StatusBarItem;
let diagnostics: vscode.DiagnosticCollection;
let scanner: CodeScanner;
let isScanning = false;

// Results Display Components
import { DiagnosticsManager, SecurityHoverProvider, ScanResultsProvider } from './ui/results';
import { SecurityCodeActionProvider } from './ui/codeActions';
import { ScanHistoryManager } from './ui/history';
import { IssueExplainer } from './ui/explainer';

let resultsProvider: ScanResultsProvider;
let diagnosticsManager: DiagnosticsManager;
let hoverProvider: SecurityHoverProvider;
let codeActionProvider: SecurityCodeActionProvider;
let scanHistoryManager: ScanHistoryManager;
let issueExplainer: IssueExplainer;

/**
 * Extension activation point
 * This method is called when the extension is activated
 */
export function activate(context: vscode.ExtensionContext) {
    Logger.info('AI Software Scanner extension is activating...');
    
    // Initialize components
    initializeExtension(context);
    
    // Register commands
    registerCommands(context);
    
    // Set up event listeners
    setupEventListeners(context);
    
    Logger.info('AI Software Scanner extension is now active!');
}

/**
 * Initialize extension components
 */
function initializeExtension(context: vscode.ExtensionContext) {
    // Initialize scanner
    scanner = new CodeScanner();
    
    // Initialize results display components
    resultsProvider = new ScanResultsProvider();
    diagnosticsManager = new DiagnosticsManager();
    hoverProvider = new SecurityHoverProvider();
    diagnostics = vscode.languages.createDiagnosticCollection('aiSoftwareScanner');
    
    // Initialize interactive features
    codeActionProvider = new SecurityCodeActionProvider();
    scanHistoryManager = new ScanHistoryManager();
    issueExplainer = new IssueExplainer();

    // Register providers
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            { scheme: 'file' },
            codeActionProvider,
            {
                providedCodeActionKinds: SecurityCodeActionProvider.providedCodeActionKinds
            }
        )
    );
    
    // Register tree view
    const treeView = vscode.window.createTreeView('aiSoftwareScannerResults', {
        treeDataProvider: resultsProvider,
        showCollapseAll: true
    });
    
    // Register hover provider
    const hoverDisposable = vscode.languages.registerHoverProvider(
        { scheme: 'file' },
        hoverProvider
    );
    
    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'ai-software-scanner.scanFile';
    updateStatusBar('Ready');
    statusBarItem.show();
    
    // Add to subscriptions
    context.subscriptions.push(
        treeView,
        hoverDisposable,
        diagnosticsManager,
        statusBarItem
    );
}

/**
 * Register extension commands
 */
function registerCommands(context: vscode.ExtensionContext) {
    // Scan current file command
    const scanFileCommand = vscode.commands.registerCommand('ai-software-scanner.scanFile', async () => {
        await scanCurrentFile();
    });
    
    // Scan workspace command
    const scanWorkspaceCommand = vscode.commands.registerCommand('ai-software-scanner.scanWorkspace', async () => {
        await scanWorkspace();
    });
    
    // Clear results command
    const clearResultsCommand = vscode.commands.registerCommand('ai-software-scanner.clearResults', () => {
        clearAllResults();
    });
    
    // Show extension settings command
    const showSettingsCommand = vscode.commands.registerCommand('ai-software-scanner.showSettings', () => {
        vscode.commands.executeCommand('workbench.action.openSettings', 'aiSoftwareScanner');
    });

    // Command to explain an issue in detail
    const explainIssueCommand = vscode.commands.registerCommand(
        'aiSoftwareScanner.explainIssue',
        async (issue: SecurityIssue) => {
            await issueExplainer.explainIssue(issue);
        }
    );

    // Command to show scan history
    const showHistoryCommand = vscode.commands.registerCommand(
        'aiSoftwareScanner.showHistory',
        async () => {
            const history = scanHistoryManager.getHistory();
            if (history.length === 0) {
                vscode.window.showInformationMessage('No scan history available');
                return;
            }

            const items = history.map((scan, index) => ({
                label: `Scan ${index + 1}`,
                description: new Date(scan.timestamp).toLocaleString(),
                detail: `Found ${scan.totalIssues} issues`,
                index: index
            }));

            const selection = await vscode.window.showQuickPick(items, {
                placeHolder: 'Select a scan to compare with current'
            });

            if (selection) {
                const compareScan = await vscode.window.showQuickPick(
                    items.filter(item => item.index !== selection.index),
                    { placeHolder: 'Select another scan to compare with' }
                );

                if (compareScan) {
                    const report = scanHistoryManager.compareScanResults(selection.index, compareScan.index);
                    
                    // Show the comparison in a new editor
                    const doc = await vscode.workspace.openTextDocument({
                        content: report,
                        language: 'markdown'
                    });
                    await vscode.window.showTextDocument(doc, { preview: false });
                }
            }
        }
    );
    
    // Show issue details command
    const showIssueDetailsCommand = vscode.commands.registerCommand(
        'aiSoftwareScanner.showIssueDetails',
        (issue: SecurityIssue) => {
            const message = new vscode.MarkdownString();
            message.isTrusted = true;
            message.supportHtml = true;

            message.appendMarkdown(`# Security Issue: ${issue.type}\n\n`);
            message.appendMarkdown(`**Severity:** ${issue.severity}\n\n`);
            message.appendMarkdown(`**Location:** Line ${issue.line}, Column ${issue.column}\n\n`);
            
            if (issue.cwe) {
                message.appendMarkdown(`**CWE:** [${issue.cwe}](https://cwe.mitre.org/data/definitions/${issue.cwe.replace('CWE-', '')}.html)\n\n`);
            }
            
            message.appendMarkdown(`**Description:**\n${issue.description || issue.message}\n\n`);
            
            if (issue.remediation) {
                message.appendMarkdown(`**Remediation:**\n${issue.remediation}`);
            }

            vscode.window.showInformationMessage('Issue Details', { modal: true }, 'View Details')
                .then(selection => {
                    if (selection === 'View Details') {
                        const panel = vscode.window.createWebviewPanel(
                            'securityIssueDetails',
                            'Security Issue Details',
                            vscode.ViewColumn.One,
                            { enableScripts: true }
                        );
                        panel.webview.html = `
                            <!DOCTYPE html>
                            <html>
                            <head>
                                <style>
                                    body { padding: 20px; }
                                    .severity { font-weight: bold; }
                                    .severity-error { color: #d73a49; }
                                    .severity-warning { color: #e36209; }
                                    .severity-info { color: #0366d6; }
                                </style>
                            </head>
                            <body>
                                <h1>${issue.type}</h1>
                                <p class="severity severity-${issue.severity}">${issue.severity.toUpperCase()}</p>
                                <p><strong>Location:</strong> Line ${issue.line}, Column ${issue.column}</p>
                                ${issue.cwe ? `<p><strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/${issue.cwe.replace('CWE-', '')}.html">${issue.cwe}</a></p>` : ''}
                                <h2>Description</h2>
                                <p>${issue.description || issue.message}</p>
                                ${issue.remediation ? `<h2>Remediation</h2><p>${issue.remediation}</p>` : ''}
                            </body>
                            </html>
                        `;
                    }
                });
        }
    );

    // Add commands to subscriptions
    context.subscriptions.push(
        scanFileCommand,
        scanWorkspaceCommand,
        clearResultsCommand,
        showSettingsCommand,
        showIssueDetailsCommand,
        explainIssueCommand,
        showHistoryCommand
    );
}

/**
 * Set up event listeners
 */
function setupEventListeners(context: vscode.ExtensionContext) {
    // Listen for active editor changes
    const onDidChangeActiveEditor = vscode.window.onDidChangeActiveTextEditor((editor) => {
        if (editor) {
            updateStatusBar('Ready');
        }
    });
    
    // Listen for configuration changes
    const onDidChangeConfiguration = vscode.workspace.onDidChangeConfiguration((event) => {
        if (event.affectsConfiguration('aiSoftwareScanner')) {
            Logger.info('Configuration changed, reloading settings...');
            // Reload scanner configuration if needed
        }
    });
    
    context.subscriptions.push(onDidChangeActiveEditor, onDidChangeConfiguration);
}

/**
 * Scan the currently active file
 */
async function scanCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No file is currently open to scan');
        return;
    }

    try {
        isScanning = true;
        updateStatusBar('Scanning...');

        const currentDoc = editor.document;

        // Clear previous results for this file
        diagnosticsManager.clearDiagnostics(currentDoc.uri.fsPath);
        resultsProvider.clearResults();
        hoverProvider.clearIssues(currentDoc.uri.fsPath);

        // Get scan options from configuration
        const config = vscode.workspace.getConfiguration('aiSoftwareScanner');
        const options: ScanOptions = {
            includeAI: config.get('useAI', true),
            scanScope: 'file',
            languages: config.get('languages', ['javascript', 'typescript', 'python', 'java'])
        };

        // Perform scan with progress indicator
        const results = await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Scanning file",
            cancellable: false
        }, async (progress) => {
            progress.report({ message: `Analyzing ${currentDoc.fileName}...` });
            Logger.info(`Starting scan of ${currentDoc.fileName}`);
            return await scanner.scanFile(currentDoc, options);
        });
        
        // Update all result views
        if (results.issues.length > 0) {
            diagnosticsManager.updateDiagnostics(currentDoc.uri.fsPath, results.issues);
            resultsProvider.updateResults(currentDoc.uri.fsPath, results.issues);
            hoverProvider.updateIssues(currentDoc.uri.fsPath, results.issues);
            codeActionProvider.updateDiagnostics(currentDoc.uri.fsPath, results.issues);
            
            // Add to scan history
            const fileIssues: { [key: string]: SecurityIssue[] } = {
                [currentDoc.uri.fsPath]: results.issues
            };
            scanHistoryManager.addScanResult(fileIssues);
        }

        updateStatusBar(`Found ${results.issues.length} issues`);
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error occurred';
        Logger.error('Scan failed:', new Error(message));
        vscode.window.showErrorMessage(`Scan failed: ${message}`);
        updateStatusBar('Scan failed');
    } finally {
        isScanning = false;
    }
    if (isScanning) {
        vscode.window.showInformationMessage('A scan is already in progress. Please wait...');
        return;
    }
    
    const document = editor.document;
    
    // Check if file type is supported
    if (!isSupportedLanguage(document.languageId)) {
        vscode.window.showWarningMessage(
            `File type '${document.languageId}' is not currently supported for scanning.`
        );
        return;
    }
    
    try {
        isScanning = true;
        updateStatusBar('Scanning...', true);
        
        const config = getConfiguration();
        const scanOptions: ScanOptions = {
            includeAI: config.enableAI,
            scanScope: 'file',
            languages: [document.languageId]
        };
        
        Logger.info(`Starting scan of file: ${document.fileName}`);
        
        // Perform the scan
        const result = await scanner.scanFile(document, scanOptions);
        
        // Clear previous diagnostics for this file
        diagnostics.delete(document.uri);
        
        // Convert scan results to VS Code diagnostics
        const vscDiagnostics = result.issues.map(issue => {
            const range = new vscode.Range(
                issue.line,
                issue.column,
                issue.endLine || issue.line,
                issue.endColumn || issue.column + 10
            );
            
            const severity = issue.severity === 'error' 
                ? vscode.DiagnosticSeverity.Error
                : issue.severity === 'warning'
                ? vscode.DiagnosticSeverity.Warning
                : vscode.DiagnosticSeverity.Information;
            
            return new vscode.Diagnostic(range, issue.message, severity);
        });
        
        // Set diagnostics
        diagnostics.set(document.uri, vscDiagnostics);
        
        const issueCount = result.issues.length;
        const message = issueCount === 0 
            ? 'No security issues found' 
            : `Found ${issueCount} security issue${issueCount > 1 ? 's' : ''}`;
        
        vscode.window.showInformationMessage(message);
        updateStatusBar(`${issueCount} issues`);
        
        Logger.info(`Scan completed. Found ${issueCount} issues in ${result.scanTime}ms`);
        
    } catch (error) {
        Logger.error('Error during file scan', error as Error);
        vscode.window.showErrorMessage(`Scan failed: ${error}`);
        updateStatusBar('Scan failed');
    } finally {
        isScanning = false;
    }
}

/**
 * Scan the entire workspace
 */
async function scanWorkspace() {
    if (!vscode.workspace.workspaceFolders) {
        vscode.window.showWarningMessage('No workspace is currently open');
        return;
    }
    
    const answer = await vscode.window.showInformationMessage(
        'This will scan all supported files in the workspace. Continue?',
        'Yes', 'No'
    );
    
    if (answer !== 'Yes') {
        return;
    }

    if (isScanning) {
        vscode.window.showInformationMessage('A scan is already in progress. Please wait...');
        return;
    }

    try {
        isScanning = true;
        updateStatusBar('Scanning workspace...', true);
        Logger.info('Starting workspace scan');

        const config = vscode.workspace.getConfiguration('aiSoftwareScanner');
        const scanOptions: ScanOptions = {
            includeAI: config.get('useAI', true),
            scanScope: 'workspace',
            languages: config.get('languages', [
                'javascript', 
                'typescript', 
                'python',
                'java',
                'cpp',
                'c',
                'csharp'
            ])
        };

        // Clear all previous results
        clearAllResults();

        let scannedFiles = 0;
        let totalIssuesFound = 0;
        const files = await vscode.workspace.findFiles(
            config.get('include', '**/*.{js,ts,py,java,cpp,c,cs}'),
            config.get('exclude', '**/node_modules/**')
        );

        // Create object to collect all issues
        const allIssues: { [key: string]: SecurityIssue[] } = {};

        // Show progress notification
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Scanning workspace",
            cancellable: true
        }, async (progress, token) => {
            // Process files in batches
            const batchSize = 10;
            for (let i = 0; i < files.length && !token.isCancellationRequested; i += batchSize) {
                const batch = files.slice(i, i + batchSize);
                progress.report({
                    message: `Scanning files... (${i + 1}/${files.length})`,
                    increment: (batch.length / files.length) * 100
                });

                await Promise.all(batch.map(async (uri) => {
                    try {
                        const document = await vscode.workspace.openTextDocument(uri);
                        const results = await scanner.scanFile(document, scanOptions);
                        scannedFiles++;

                        if (results.issues.length > 0) {
                            diagnosticsManager.updateDiagnostics(uri.fsPath, results.issues);
                            resultsProvider.updateResults(uri.fsPath, results.issues);
                            hoverProvider.updateIssues(uri.fsPath, results.issues);
                            codeActionProvider.updateDiagnostics(uri.fsPath, results.issues);
                            totalIssuesFound += results.issues.length;

                            // Collect issues for history
                            allIssues[uri.fsPath] = results.issues;
                        }
                    } catch (error) {
                        Logger.error(`Error scanning ${uri.fsPath}:`, error as Error);
                    }
                }));

                // Add scan result to history
                if (totalIssuesFound > 0) {
                    scanHistoryManager.addScanResult(allIssues);
                }
            }
        });

        // Show completion message
        const resultMessage = totalIssuesFound > 0
            ? `Found ${totalIssuesFound} issue${totalIssuesFound === 1 ? '' : 's'} across ${scannedFiles} files`
            : `No issues found in ${scannedFiles} files`;

        updateStatusBar(resultMessage);
        vscode.window.showInformationMessage(resultMessage);

    } catch (error) {
        Logger.error('Error during workspace scan', error as Error);
        vscode.window.showErrorMessage(`Workspace scan failed: ${error}`);
        updateStatusBar('Scan failed');
    } finally {
        isScanning = false;
    }
}

/**
 * Clear all scan results
 */
function clearAllResults() {
    diagnosticsManager.clearDiagnostics();
    resultsProvider.clearResults();
    hoverProvider.clearIssues();
    updateStatusBar('Ready');
    vscode.window.showInformationMessage('All scan results cleared');
    Logger.info('Cleared all scan results');
}

/**
 * Update the status bar item
 */
function updateStatusBar(text: string, isLoading = false) {
    if (!statusBarItem) {
        return;
    }

    statusBarItem.text = `$(shield) AI Scanner: ${text}`;
    statusBarItem.tooltip = isLoading 
        ? 'Scanning in progress...' 
        : 'Click to scan current file';
    statusBarItem.show();
}

/**
 * Check if a language is supported for scanning
 */
function isSupportedLanguage(languageId: string): boolean {
    const supportedLanguages = [
        'javascript', 'typescript', 'python', 'java', 'csharp',
        'php', 'go', 'rust', 'cpp', 'c', 'html', 'css', 'json'
    ];
    return supportedLanguages.includes(languageId);
}

/**
 * Get extension configuration
 */
function getConfiguration() {
    const config = vscode.workspace.getConfiguration('aiSoftwareScanner');
    return {
        enableAI: config.get<boolean>('enableAI', false),
        apiKey: config.get<string>('apiKey', ''),
        scanOnSave: config.get<boolean>('scanOnSave', false),
        maxIssuesPerFile: config.get<number>('maxIssuesPerFile', 50)
    };
}

/**
 * Extension deactivation point
 */
export function deactivate() {
    Logger.info('AI Software Scanner extension is deactivating...');
    
    if (statusBarItem) {
        statusBarItem.dispose();
    }
    
    if (diagnosticsManager) {
        diagnosticsManager.dispose();
    }
    
    Logger.info('AI Software Scanner extension deactivated');
}