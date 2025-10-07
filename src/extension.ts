// The module 'vscode' contains the VS Code extensibility API
import * as vscode from 'vscode';
import { Logger } from './utils';
import { CodeScanner, ScanOptions } from './scanner';

// Global extension state
let statusBarItem: vscode.StatusBarItem;
let diagnostics: vscode.DiagnosticCollection;
let scanner: CodeScanner;
let isScanning = false;

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
    
    // Create diagnostics collection
    diagnostics = vscode.languages.createDiagnosticCollection('ai-security-scanner');
    context.subscriptions.push(diagnostics);
    
    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'ai-software-scanner.scanFile';
    updateStatusBar('Ready');
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);
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
    
    // Add commands to subscriptions
    context.subscriptions.push(
        scanFileCommand,
        scanWorkspaceCommand,
        clearResultsCommand,
        showSettingsCommand
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
async function scanCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No file is currently open to scan');
        return;
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
    
    vscode.window.showInformationMessage('Workspace scanning is not yet implemented. This feature will be added in future milestones.');
}

/**
 * Clear all scan results
 */
function clearAllResults() {
    diagnostics.clear();
    updateStatusBar('Ready');
    vscode.window.showInformationMessage('All scan results cleared');
    Logger.info('Cleared all scan results');
}

/**
 * Update the status bar item
 */
function updateStatusBar(text: string, isLoading = false) {
    statusBarItem.text = `$(shield) AI Scanner: ${text}`;
    statusBarItem.tooltip = isLoading 
        ? 'Scanning in progress...' 
        : 'Click to scan current file';
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
    
    if (diagnostics) {
        diagnostics.dispose();
    }
    
    Logger.info('AI Software Scanner extension deactivated');
}