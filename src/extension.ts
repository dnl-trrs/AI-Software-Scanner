/**
 * AI-Based Software Code Security Analysis & Recommendation
 * VS Code Extension Main Entry Point
 * 
 * This tool provides:
 * - Vulnerability detection with actionable fixes
 * - Educational content for developers
 * - Best practice recommendations
 * 
 * Key differentiator: Unlike Snyk AI, Zerothreat, and Qwiet AI,
 * we provide both detection AND automated fix suggestions with education.
 */

import * as vscode from 'vscode';
import * as dotenv from 'dotenv';
import * as path from 'path';
import * as fs from 'fs';
import SecurityScanner from './scanner/SecurityScanner';
import AIRecommendationEngine from './ai/AIRecommendationEngine';
import { SecurityPanelProvider } from './ui/SecurityPanel';
import { Vulnerability } from './scanner/SecurityScanner';
import { SidebarProvider } from './ui/SidebarProvider';
import { RecommendationDecorator, Recommendation } from './ui/RecommendationDecorator';
import { RecommendationPanel } from './ui/RecommendationPanel';

let scanner: SecurityScanner;
let aiEngine: AIRecommendationEngine;
let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;
let sidebarProvider: SidebarProvider;
let recommendationDecorator: RecommendationDecorator;
let currentRecommendations: any[] = [];
let acceptedCount: number = 0;
let filesScannedCount: number = 0;

// Track scanned files to prevent duplicate scans
let scannedFiles = new Set<string>();
let fileHashes = new Map<string, string>();
let isScanning = false;

export function activate(context: vscode.ExtensionContext) {
    console.log('🔒 AI Software Security Scanner is now active!');

    // Try to load .env file from workspace
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (workspaceFolders && workspaceFolders.length > 0) {
        const envPath = path.join(workspaceFolders[0].uri.fsPath, '.env');
        if (fs.existsSync(envPath)) {
            dotenv.config({ path: envPath });
            console.log('Loaded .env file from workspace');
        }
    }

    // Get API key from configuration or environment
    const config = vscode.workspace.getConfiguration('aiSecurityScanner');
    let apiKey = config.get<string>('openaiApiKey');
    
    // If not in settings, try environment variable
    if (!apiKey || apiKey === '') {
        apiKey = process.env.OPENAI_API_KEY;
    }
    
    if (!apiKey || apiKey === '') {
        const selection = vscode.window.showWarningMessage(
            'OpenAI API key not configured. The scanner will use pattern-based detection.',
            'Add API Key'
        );
        
        selection.then(value => {
            if (value === 'Add API Key') {
                vscode.window.showInputBox({
                    prompt: 'Enter your OpenAI API Key',
                    password: true,
                    placeHolder: 'sk-...'
                }).then(key => {
                    if (key) {
                        config.update('openaiApiKey', key, vscode.ConfigurationTarget.Global);
                        vscode.window.showInformationMessage('API Key saved. Please reload the window to apply changes.');
                    }
                });
            }
        });
    } else {
        console.log('API Key configured successfully');
    }

    // Initialize components with API key
    scanner = new SecurityScanner(apiKey);
    aiEngine = new AIRecommendationEngine(apiKey);
    diagnosticCollection = vscode.languages.createDiagnosticCollection('security');
    outputChannel = vscode.window.createOutputChannel('Security Scanner');
    recommendationDecorator = new RecommendationDecorator();
    
    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.text = '$(shield) Security';
    statusBarItem.tooltip = 'AI Software Security Scanner - Click to demo UI';
    statusBarItem.command = 'ai-software-scanner.demoUI';
    statusBarItem.show();

    // Register sidebar provider
    sidebarProvider = new SidebarProvider(context.extensionUri, context);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            SidebarProvider.viewType,
            sidebarProvider
        )
    );

    // Register commands
    const scanFileCommand = vscode.commands.registerCommand('ai-software-scanner.scanFile', async () => {
        // When explicitly triggered by user, force scan even if already scanned
        await scanCurrentFile(true);
    });

    const scanWorkspaceCommand = vscode.commands.registerCommand('ai-software-scanner.scanWorkspace', async () => {
        await scanWorkspace();
    });

    const showPanelCommand = vscode.commands.registerCommand('ai-software-scanner.showSecurityPanel', () => {
        SecurityPanelProvider.createOrShow(context.extensionUri);
    });

    const applyFixCommand = vscode.commands.registerCommand('ai-software-scanner.applyFix', async (vulnerability: Vulnerability, fix: string) => {
        await applySecurityFix(vulnerability, fix);
    });

    const showEducationalContentCommand = vscode.commands.registerCommand('ai-software-scanner.showEducation', (content: string) => {
        showEducationalContent(content);
    });

    // New UI Commands
    const showRecommendationsCommand = vscode.commands.registerCommand('ai-software-scanner.showRecommendations', () => {
        if (currentRecommendations.length > 0) {
            RecommendationPanel.createOrShow(context.extensionUri, currentRecommendations);
        } else {
            vscode.window.setStatusBarMessage('No recommendations available. Run a scan first!', 3000);
        }
    });

    const acceptRecommendationCommand = vscode.commands.registerCommand('ai-software-scanner.acceptRecommendation', async (data: any) => {
        try {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('No active editor to apply fix');
                return;
            }
            
            // Get the vulnerability and fix from the data
            const { vulnerability, fix } = data;
            
            if (!vulnerability || !fix) {
                vscode.window.showErrorMessage('Invalid fix data');
                return;
            }
            
            // Apply the fix to the document
            await editor.edit((editBuilder) => {
                const line = vulnerability.line - 1; // Convert to 0-based
                const lineText = editor.document.lineAt(line);
                const range = new vscode.Range(
                    line, 0,
                    line, lineText.text.length
                );
                
                // Replace the vulnerable line with the fix
                editBuilder.replace(range, fix);
            });
            
            acceptedCount++;
            
            // Update sidebar stats
            if (sidebarProvider) {
                sidebarProvider.updateStats({
                    recommendationsCount: currentRecommendations.length - acceptedCount,
                    issuesFixed: acceptedCount,
                    filesScanned: filesScannedCount
                });
            }
            
            // Show temporary status message
            vscode.window.setStatusBarMessage(`✅ Fix applied (${acceptedCount} fixed so far)`, 3000);
            
            // Remove from current recommendations
            currentRecommendations = currentRecommendations.filter(r => r.vulnerabilityId !== vulnerability.id);
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to apply fix: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    });

    const declineRecommendationCommand = vscode.commands.registerCommand('ai-software-scanner.declineRecommendation', (data: any) => {
        // Show temporary status message
        vscode.window.setStatusBarMessage(`Recommendation declined`, 2000);
    });

    const learnMoreCommand = vscode.commands.registerCommand('ai-software-scanner.learnMore', (type: string) => {
        showEducationalContent(`<h3>${type}</h3><p>Educational content about this security issue would appear here...</p>`);
    });

    // Demo command to show the UI
    const demoUICommand = vscode.commands.registerCommand('ai-software-scanner.demoUI', () => {
        showDemoRecommendations();
    });
    
    // Command to clear scan cache
    const clearCacheCommand = vscode.commands.registerCommand('ai-software-scanner.clearCache', () => {
        scannedFiles.clear();
        fileHashes.clear();
        vscode.window.showInformationMessage('Scan cache cleared. Files will be rescanned on next request.');
    });

    // Register code actions provider for quick fixes
    const codeActionProvider = vscode.languages.registerCodeActionsProvider(
        { scheme: 'file', language: '*' },
        new SecurityCodeActionProvider(scanner, aiEngine),
        {
            providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
        }
    );

    // Auto-scan on file save
    const onSaveListener = vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('aiSecurityScanner');
        if (config.get<boolean>('scanOnSave') && shouldScanDocument(document)) {
            const fileName = document.fileName;
            const fileContent = document.getText();
            const contentHash = generateHash(fileContent);
            
            // Only rescan if content changed
            if (fileHashes.get(fileName) !== contentHash) {
                await scanDocument(document);
                scannedFiles.add(fileName);
                fileHashes.set(fileName, contentHash);
            }
        }
    });

    // Auto-scan on file open (disabled by default to prevent duplicate scans)
    const onOpenListener = vscode.window.onDidChangeActiveTextEditor(async (editor) => {
        if (editor) {
            const config = vscode.workspace.getConfiguration('aiSecurityScanner');
            const fileName = editor.document.fileName;
            
            // Only scan if explicitly enabled and file hasn't been scanned
            if (config.get<boolean>('scanOnOpen') && 
                !scannedFiles.has(fileName) && 
                shouldScanDocument(editor.document)) {
                await scanDocument(editor.document);
                scannedFiles.add(fileName);
                fileHashes.set(fileName, generateHash(editor.document.getText()));
            }
        }
    });

    // Add to subscriptions
    context.subscriptions.push(
        scanFileCommand,
        scanWorkspaceCommand,
        showPanelCommand,
        applyFixCommand,
        showEducationalContentCommand,
        showRecommendationsCommand,
        acceptRecommendationCommand,
        declineRecommendationCommand,
        learnMoreCommand,
        demoUICommand,
        clearCacheCommand,
        codeActionProvider,
        diagnosticCollection,
        statusBarItem,
        outputChannel,
        onSaveListener,
        onOpenListener,
        recommendationDecorator
    );

    // Show welcome message in status bar instead of notification
    vscode.window.setStatusBarMessage('🛡️ AI Security Scanner activated!', 5000);
}

/**
 * Scan the current file for vulnerabilities
 */
async function scanCurrentFile(force: boolean = false) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.setStatusBarMessage('⚠️ No active file to scan', 3000);
        return;
    }

    const fileName = editor.document.fileName;
    const fileContent = editor.document.getText();
    const contentHash = generateHash(fileContent);
    
    // Check if file has already been scanned with same content
    if (!force && scannedFiles.has(fileName) && fileHashes.get(fileName) === contentHash) {
        vscode.window.setStatusBarMessage('✓ File already scanned', 2000);
        return;
    }
    
    // Prevent concurrent scans
    if (isScanning) {
        vscode.window.setStatusBarMessage('⏳ Scan already in progress...', 2000);
        return;
    }

    filesScannedCount++;
    await scanDocument(editor.document);
    
    // Mark file as scanned
    scannedFiles.add(fileName);
    fileHashes.set(fileName, contentHash);
}

/**
 * Generate hash for content comparison
 */
function generateHash(content: string): string {
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
        const char = content.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32bit integer
    }
    return hash.toString();
}

/**
 * Scan a document for vulnerabilities
 */
async function scanDocument(document: vscode.TextDocument) {
    if (isScanning) {
        return;
    }
    
    isScanning = true;
    outputChannel.appendLine(`\n🔍 Scanning ${document.fileName}...`);
    
    try {
        // Show progress
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Scanning for security vulnerabilities...',
            cancellable: false
        }, async (progress) => {
        progress.report({ increment: 20, message: 'Analyzing code patterns...' });
        
        // Scan for vulnerabilities
        const vulnerabilities = await scanner.scanFile(document);
        
        progress.report({ increment: 40, message: 'Generating AI recommendations...' });
        
        // Generate AI recommendations
        const recommendations = await aiEngine.generateBatchRecommendations(vulnerabilities);
        
        progress.report({ increment: 30, message: 'Processing results...' });
        
        // Update diagnostics
        await updateDiagnostics(document, vulnerabilities);
        
        // Update status bar
        updateStatusBar(vulnerabilities);
        
        // Log results
        logScanResults(vulnerabilities, recommendations);
        
        progress.report({ increment: 10, message: 'Complete!' });
        
        // Store recommendations globally with vulnerability data for accept button
        currentRecommendations = recommendations.map((rec, index) => {
            const vuln = vulnerabilities[index];
            return {
                ...rec,
                vulnerability: {
                    ...vuln,
                    // Ensure we have the actual code line
                    code: vuln.code || document.lineAt(Math.max(0, vuln.line - 1)).text,
                    line: vuln.line,
                    column: vuln.column || 1,
                    type: vuln.type,
                    message: vuln.message,
                    severity: vuln.severity,
                    recommendation: vuln.recommendation,
                    educationalContent: vuln.educationalContent,
                    automaticFix: vuln.automaticFix
                }
            };
        });
        
        // Show summary
        showScanSummary(vulnerabilities, recommendations);
        
        // Update security panel if open
        SecurityPanelProvider.update(vulnerabilities, recommendations);
        });
    } catch (error) {
        console.error('Scan error:', error);
        vscode.window.showErrorMessage(`Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
        isScanning = false;
    }
}

/**
 * Scan entire workspace
 */
async function scanWorkspace() {
    const files = await vscode.workspace.findFiles(
        '**/*.{js,ts,jsx,tsx,py,java,go,rb,php,cs,cpp,c}',
        '**/node_modules/**'
    );
    
    vscode.window.showInformationMessage(`Found ${files.length} files to scan`);
    
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Scanning workspace...',
        cancellable: true
    }, async (progress, token) => {
        let scanned = 0;
        const allVulnerabilities: Vulnerability[] = [];
        
        for (const file of files) {
            if (token.isCancellationRequested) {
                break;
            }
            
            const document = await vscode.workspace.openTextDocument(file);
            const vulnerabilities = await scanner.scanFile(document);
            allVulnerabilities.push(...vulnerabilities);
            
            scanned++;
            progress.report({
                increment: (100 / files.length),
                message: `Scanned ${scanned}/${files.length} files`
            });
        }
        
        // Generate summary
        const stats = scanner.getStatistics();
        vscode.window.showInformationMessage(
            `Scan complete! Found ${stats.total} vulnerabilities: ` +
            `${stats.critical} critical, ${stats.high} high, ${stats.medium} medium, ${stats.low} low`
        );
    });
}

/**
 * Update VS Code diagnostics (problems panel)
 */
async function updateDiagnostics(document: vscode.TextDocument, vulnerabilities: Vulnerability[]) {
    const diagnostics: vscode.Diagnostic[] = vulnerabilities.map(vuln => {
        const range = new vscode.Range(
            vuln.line - 1,
            vuln.column - 1,
            vuln.endLine ? vuln.endLine - 1 : vuln.line - 1,
            vuln.endColumn ? vuln.endColumn - 1 : vuln.column + 10
        );
        
        const diagnostic = new vscode.Diagnostic(
            range,
            vuln.message,
            severityToVSCode(vuln.severity)
        );
        
        diagnostic.code = vuln.type;
        diagnostic.source = 'AI Security Scanner';
        
        // Add our unique educational content to the diagnostic
        if (vuln.recommendation) {
            diagnostic.message = `${vuln.message}\n\n💡 Fix: ${vuln.recommendation}`;
        }
        
        return diagnostic;
    });
    
    diagnosticCollection.set(document.uri, diagnostics);
}

/**
 * Convert our severity to VS Code diagnostic severity
 */
function severityToVSCode(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'critical':
        case 'high':
            return vscode.DiagnosticSeverity.Error;
        case 'medium':
            return vscode.DiagnosticSeverity.Warning;
        case 'low':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Hint;
    }
}

/**
 * Update status bar with scan results
 */
function updateStatusBar(vulnerabilities: Vulnerability[]) {
    const critical = vulnerabilities.filter(v => v.severity === 'critical').length;
    const high = vulnerabilities.filter(v => v.severity === 'high').length;
    
    if (critical > 0) {
        statusBarItem.text = `$(shield) ${critical} Critical`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    } else if (high > 0) {
        statusBarItem.text = `$(shield) ${high} High`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    } else if (vulnerabilities.length > 0) {
        statusBarItem.text = `$(shield) ${vulnerabilities.length} Issues`;
        statusBarItem.backgroundColor = undefined;
    } else {
        statusBarItem.text = '$(shield) Secure ✓';
        statusBarItem.backgroundColor = undefined;
    }
}

/**
 * Log scan results to output channel
 */
function logScanResults(vulnerabilities: Vulnerability[], recommendations: any[]) {
    outputChannel.appendLine(`\n📊 Scan Results:`);
    outputChannel.appendLine(`Found ${vulnerabilities.length} vulnerabilities\n`);
    
    vulnerabilities.forEach((vuln, index) => {
        outputChannel.appendLine(`${index + 1}. [${vuln.severity.toUpperCase()}] ${vuln.type}`);
        outputChannel.appendLine(`   Line ${vuln.line}: ${vuln.message}`);
        if (recommendations[index]) {
            outputChannel.appendLine(`   ⚡ Quick Fix Available (${recommendations[index].estimatedFixTime} min)`);
            outputChannel.appendLine(`   📚 ${recommendations[index].learningResources.length} learning resources available`);
        }
        outputChannel.appendLine('');
    });
    
    outputChannel.show(true);
}

/**
 * Show scan summary in status bar
 */
function showScanSummary(vulnerabilities: Vulnerability[], recommendations: any[]) {
    if (vulnerabilities.length === 0) {
        vscode.window.setStatusBarMessage('✅ No security vulnerabilities found!', 3000);
        return;
    }
    
    const summary = aiEngine.generateSummary(recommendations);
    const message = `Found ${vulnerabilities.length} vulnerabilities. Est. fix time: ${summary.totalFixTime} min`;
    
    // Update status bar and sidebar
    vscode.window.setStatusBarMessage(`🔍 ${message}`, 5000);
    
    // Don't overwrite currentRecommendations here - it's already set properly in scanDocument
    // currentRecommendations = recommendations; // REMOVED - this was overwriting the good data
    
    // Update sidebar
    if (sidebarProvider) {
        sidebarProvider.updateStats({
            recommendationsCount: vulnerabilities.length,
            issuesFixed: acceptedCount,
            filesScanned: filesScannedCount,
            lastScan: new Date().toLocaleTimeString()
        });
        
        // Show first few results in sidebar
        sidebarProvider.showScanResults(vulnerabilities.slice(0, 5));
    }
}

/**
 * Apply a security fix
 */
async function applySecurityFix(vulnerability: Vulnerability, fix: string) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;
    
    const edit = new vscode.WorkspaceEdit();
    const range = new vscode.Range(
        vulnerability.line - 1,
        0,
        vulnerability.endLine ? vulnerability.endLine - 1 : vulnerability.line - 1,
        editor.document.lineAt(vulnerability.endLine ? vulnerability.endLine - 1 : vulnerability.line - 1).text.length
    );
    
    edit.replace(editor.document.uri, range, fix);
    await vscode.workspace.applyEdit(edit);
    
    vscode.window.showInformationMessage(`✅ Applied fix for ${vulnerability.type}`);
}

/**
 * Apply all automated fixes
 */
async function applyAllFixes(vulnerabilities: Vulnerability[], recommendations: any[]) {
    let applied = 0;
    
    for (let i = 0; i < vulnerabilities.length; i++) {
        if (recommendations[i] && recommendations[i].automaticFix) {
            await applySecurityFix(vulnerabilities[i], recommendations[i].automaticFix);
            applied++;
        }
    }
    
    vscode.window.showInformationMessage(`✅ Applied ${applied} automated fixes`);
}

/**
 * Show educational content in a webview
 */
function showEducationalContent(content: string) {
    const panel = vscode.window.createWebviewPanel(
        'securityEducation',
        'Security Education',
        vscode.ViewColumn.Two,
        {}
    );
    
    panel.webview.html = `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    padding: 20px;
                    line-height: 1.6;
                }
                h2 { color: #e74c3c; }
                .tip { 
                    background: #f0f0f0;
                    padding: 10px;
                    border-left: 4px solid #3498db;
                    margin: 10px 0;
                }
            </style>
        </head>
        <body>
            <h2>🎓 Security Learning</h2>
            ${content}
            <div class="tip">
                <strong>💡 Remember:</strong> Security is not just about finding vulnerabilities, 
                but understanding and preventing them. This educational approach is what sets us 
                apart from competitors like Snyk AI and Qwiet AI.
            </div>
        </body>
        </html>
    `;
}

/**
 * Check if document should be scanned
 */
function shouldScanDocument(document: vscode.TextDocument): boolean {
    const supportedLanguages = ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'cpp', 'c'];
    return supportedLanguages.includes(document.languageId);
}

/**
 * Demo function to show the UI with sample recommendations
 */
function showDemoRecommendations() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.setStatusBarMessage('⚠️ Please open a file to see demo recommendations', 3000);
        return;
    }
    
    // Reset counters for demo
    acceptedCount = 0;
    filesScannedCount = 1;

    // Sample recommendations matching your Figma mockup - expanded with more examples
    const demoRecommendations: Recommendation[] = [
        {
            line: 12,
            column: 20,
            endLine: 12,
            endColumn: 60,
            severity: 'critical',
            type: 'SQL Injection',
            message: 'Direct string concatenation in SQL query creates SQL injection vulnerability',
            suggestion: 'Use parameterized queries or prepared statements to prevent SQL injection'
        },
        {
            line: 23,
            column: 12,
            endLine: 23,
            endColumn: 45,
            severity: 'high',
            type: 'Weak Random Generation',
            message: 'Math.random() is not cryptographically secure for tokens',
            suggestion: 'Use crypto.randomBytes() or similar cryptographic random functions'
        },
        {
            line: 30,
            column: 15,
            endLine: 30,
            endColumn: 40,
            severity: 'critical',
            type: 'Hardcoded Password',
            message: 'Password stored in plain text in source code',
            suggestion: 'Use environment variables or secure secret management systems'
        },
        {
            line: 37,
            column: 10,
            endLine: 37,
            endColumn: 55,
            severity: 'high',
            type: 'XSS Vulnerability',
            message: 'User input directly rendered without sanitization',
            suggestion: 'Sanitize user input before rendering to prevent XSS attacks'
        },
        {
            line: 54,
            column: 18,
            endLine: 54,
            endColumn: 35,
            severity: 'critical',
            type: 'Code Injection',
            message: 'Using eval() with user input is extremely dangerous',
            suggestion: 'Parse and validate input instead of using eval()'
        },
        {
            line: 61,
            column: 20,
            endLine: 61,
            endColumn: 90,
            severity: 'medium',
            type: 'ExpDistribution',
            message: 'Potential security vulnerability detected in probability distribution',
            suggestion: 'Consider using a more secure random number generation method'
        },
        {
            line: 62,
            column: 20,
            endLine: 62,
            endColumn: 75,
            severity: 'high',
            type: 'InsecureRandomValue',
            message: 'Using predictable random values can lead to security vulnerabilities',
            suggestion: 'Use cryptographically secure random number generation'
        },
        {
            line: 81,
            column: 30,
            endLine: 82,
            endColumn: 95,
            severity: 'medium',
            type: 'Missing Input Validation',
            message: 'User input used without proper validation',
            suggestion: 'Validate and sanitize all user inputs before processing'
        }
    ];

    // Apply decorations to show inline recommendations
    recommendationDecorator.setRecommendations(
        editor.document.uri.toString(),
        demoRecommendations
    );

    // Store recommendations globally with proper vulnerability structure
    currentRecommendations = demoRecommendations.map((rec, index) => ({
        vulnerabilityId: `demo-${index}`,
        vulnerability: {
            id: `demo-${index}`,
            type: rec.type,
            severity: rec.severity,
            line: rec.line,
            column: rec.column || 1,
            message: rec.message,
            code: getExampleCode(rec.type, 'before'),
            recommendation: rec.suggestion,
            educationalContent: getExplanation(rec.type),
            automaticFix: getExampleCode(rec.type, 'after'),
            file: editor.document.fileName
        },
        automaticFix: getExampleCode(rec.type, 'after'),
        explanation: getExplanation(rec.type),
        bestPractices: [`Always validate input`, `Use secure coding practices`],
        alternativeSolutions: [`Consider using a security library`],
        estimatedFixTime: 10,
        confidence: 90,
        learningResources: []
    }));
    
    // Update sidebar with stats and scan results
    sidebarProvider.updateStats({
        recommendationsCount: demoRecommendations.length,
        issuesFixed: 0,
        filesScanned: 1,
        lastScan: new Date().toLocaleTimeString()
    });
    
    // Show scan results in sidebar
    sidebarProvider.showScanResults(demoRecommendations.slice(0, 5)); // Show first 5 in sidebar

    // Don't automatically open the panel - let user click 'View All Recommendations'
    vscode.window.setStatusBarMessage(`🔍 Scan complete! Found ${demoRecommendations.length} issues. Click 'View All Recommendations' in sidebar.`, 5000);

    // Log to output channel without showing notification
    outputChannel.appendLine('\n=== Demo Scan Complete ===');
    outputChannel.appendLine(`Found ${demoRecommendations.length} security issues:`);
    
    // Group by severity
    const bySeverity = {
        critical: demoRecommendations.filter(r => r.severity === 'critical'),
        high: demoRecommendations.filter(r => r.severity === 'high'),
        medium: demoRecommendations.filter(r => r.severity === 'medium'),
        low: demoRecommendations.filter(r => r.severity === 'low')
    };
    
    outputChannel.appendLine(`\nCritical: ${bySeverity.critical.length} | High: ${bySeverity.high.length} | Medium: ${bySeverity.medium.length} | Low: ${bySeverity.low.length}`);
    outputChannel.appendLine('\nCheck the sidebar for details or click "View All Recommendations" to review.');
}

/**
 * Helper function to get example code for different vulnerability types
 */
function getExampleCode(type: string, version: 'before' | 'after'): string {
    const examples: Record<string, { before: string; after: string }> = {
        'SQL Injection': {
            before: 'const query = "SELECT * FROM users WHERE id = " + userId;',
            after: 'const query = "SELECT * FROM users WHERE id = ?";\n// Use parameterized query: connection.query(query, [userId])'
        },
        'Weak Random Generation': {
            before: 'return Math.random().toString(36).substring(2);',
            after: 'const crypto = require(\'crypto\');\nreturn crypto.randomBytes(32).toString(\'hex\');'
        },
        'Hardcoded Password': {
            before: 'password: \'password123\' // Never store passwords in plain text!',
            after: 'password: process.env.DB_PASSWORD // Use environment variables'
        },
        'XSS Vulnerability': {
            before: 'res.send(`<h1>Search results for: ${searchTerm}</h1>`);',
            after: 'const sanitized = escapeHtml(searchTerm);\nres.send(`<h1>Search results for: ${sanitized}</h1>`);'
        },
        'Code Injection': {
            before: 'const result = eval(expression);',
            after: 'const result = safeCalculate(expression); // Use a safe parser'
        },
        'ExpDistribution': {
            before: 'ExpDistribution(mean: fields["mean-duration"].toDouble())',
            after: 'SecureExpDistribution(mean: fields["mean-duration"].toDouble(), entropy: SecureRandom())'
        },
        'InsecureRandomValue': {
            before: 'fields["mean-interarrival-time"].toDouble()',
            after: 'SecureRandom.nextDouble(fields["mean-interarrival-time"])'
        },
        'Missing Input Validation': {
            before: 'const input = req.body.data;\nprocessData(input);',
            after: 'const input = validateInput(req.body.data);\nif (input) processData(input);'
        }
    };
    
    return examples[type]?.[version] || (version === 'before' ? '// Vulnerable code' : '// Fixed code');
}

/**
 * Helper function to get explanations for vulnerability types
 */
function getExplanation(type: string): string {
    const explanations: Record<string, string> = {
        'SQL Injection': 'SQL injection allows attackers to execute arbitrary SQL commands, potentially accessing or destroying your database.',
        'Weak Random Generation': 'Math.random() is predictable and not suitable for security purposes like generating tokens or passwords.',
        'Hardcoded Password': 'Storing passwords in source code exposes them to anyone with repository access and makes rotation difficult.',
        'XSS Vulnerability': 'Cross-site scripting allows attackers to inject malicious scripts that run in users\' browsers.',
        'Code Injection': 'eval() executes arbitrary code, allowing attackers to run malicious commands on your server.',
        'ExpDistribution': 'Using predictable random distributions can make your application vulnerable to timing attacks.',
        'InsecureRandomValue': 'Predictable random values can be exploited by attackers to compromise security mechanisms.',
        'Missing Input Validation': 'Unvalidated input can lead to various security vulnerabilities including injection attacks.'
    };
    
    return explanations[type] || 'This vulnerability could compromise the security of your application.';
}

/**
 * Code action provider for quick fixes
 */
class SecurityCodeActionProvider implements vscode.CodeActionProvider {
    constructor(
        private scanner: SecurityScanner,
        private aiEngine: AIRecommendationEngine
    ) {}
    
    async provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext
    ): Promise<vscode.CodeAction[]> {
        const actions: vscode.CodeAction[] = [];
        
        // Get vulnerabilities for this line
        const vulnerabilities = this.scanner.getVulnerabilities().filter(v => {
            return v.line - 1 >= range.start.line && v.line - 1 <= range.end.line;
        });
        
        for (const vuln of vulnerabilities) {
            // Create quick fix action
            const fixAction = new vscode.CodeAction(
                `🔧 Fix ${vuln.type}`,
                vscode.CodeActionKind.QuickFix
            );
            
            fixAction.command = {
                command: 'ai-software-scanner.applyFix',
                title: 'Apply Security Fix',
                arguments: [vuln, vuln.recommendation]
            };
            
            actions.push(fixAction);
            
            // Create learn more action
            const learnAction = new vscode.CodeAction(
                `📚 Learn about ${vuln.type}`,
                vscode.CodeActionKind.QuickFix
            );
            
            learnAction.command = {
                command: 'ai-software-scanner.showEducation',
                title: 'Show Educational Content',
                arguments: [vuln.educationalContent]
            };
            
            actions.push(learnAction);
        }
        
        return actions;
    }
}

export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
    if (statusBarItem) {
        statusBarItem.dispose();
    }
    if (outputChannel) {
        outputChannel.dispose();
    }
}
