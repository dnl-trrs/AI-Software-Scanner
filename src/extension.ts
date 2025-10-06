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

export function activate(context: vscode.ExtensionContext) {
    console.log('🔒 AI Software Security Scanner is now active!');

    // Initialize components
    scanner = new SecurityScanner();
    aiEngine = new AIRecommendationEngine();
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
        await scanCurrentFile();
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
        vscode.window.showInformationMessage('Showing all recommendations...');
        // This would open a full recommendations view
    });

    const manageSubscriptionCommand = vscode.commands.registerCommand('ai-software-scanner.manageSubscription', () => {
        vscode.window.showInformationMessage('Opening subscription management...');
        // This would open subscription settings
    });

    const acceptRecommendationCommand = vscode.commands.registerCommand('ai-software-scanner.acceptRecommendation', async (data: any) => {
        vscode.window.showInformationMessage(`Accepting recommendation for line ${data.line}`);
        // Apply the fix here
    });

    const declineRecommendationCommand = vscode.commands.registerCommand('ai-software-scanner.declineRecommendation', (data: any) => {
        vscode.window.showInformationMessage(`Declined recommendation for line ${data.line}`);
    });

    const learnMoreCommand = vscode.commands.registerCommand('ai-software-scanner.learnMore', (type: string) => {
        showEducationalContent(`<h3>${type}</h3><p>Educational content about this security issue would appear here...</p>`);
    });

    // Demo command to show the UI
    const demoUICommand = vscode.commands.registerCommand('ai-software-scanner.demoUI', () => {
        showDemoRecommendations();
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
        if (shouldScanDocument(document)) {
            await scanDocument(document);
        }
    });

    // Auto-scan on file open
    const onOpenListener = vscode.window.onDidChangeActiveTextEditor(async (editor) => {
        if (editor && shouldScanDocument(editor.document)) {
            await scanDocument(editor.document);
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
        manageSubscriptionCommand,
        acceptRecommendationCommand,
        declineRecommendationCommand,
        learnMoreCommand,
        demoUICommand,
        codeActionProvider,
        diagnosticCollection,
        statusBarItem,
        outputChannel,
        onSaveListener,
        onOpenListener,
        recommendationDecorator
    );

    // Show welcome message with key features
    vscode.window.showInformationMessage(
        '🛡️ AI Security Scanner activated! Unlike competitors, we provide actionable fixes and educational content.',
        'Scan Current File',
        'View Documentation'
    ).then(selection => {
        if (selection === 'Scan Current File') {
            vscode.commands.executeCommand('ai-software-scanner.scanFile');
        } else if (selection === 'View Documentation') {
            vscode.env.openExternal(vscode.Uri.parse('https://github.com/dnl-trrs/AI-Software-Scanner'));
        }
    });
}

/**
 * Scan the current file for vulnerabilities
 */
async function scanCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active file to scan');
        return;
    }

    await scanDocument(editor.document);
}

/**
 * Scan a document for vulnerabilities
 */
async function scanDocument(document: vscode.TextDocument) {
    outputChannel.appendLine(`\n🔍 Scanning ${document.fileName}...`);
    
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
        
        // Show summary
        showScanSummary(vulnerabilities, recommendations);
        
        // Update security panel if open
        SecurityPanelProvider.update(vulnerabilities, recommendations);
    });
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
 * Show scan summary notification
 */
function showScanSummary(vulnerabilities: Vulnerability[], recommendations: any[]) {
    if (vulnerabilities.length === 0) {
        vscode.window.showInformationMessage('✅ No security vulnerabilities found!');
        return;
    }
    
    const summary = aiEngine.generateSummary(recommendations);
    const message = `Found ${vulnerabilities.length} vulnerabilities. ` +
                   `Estimated fix time: ${summary.totalFixTime} minutes. ` +
                   `Confidence: ${summary.averageConfidence}%`;
    
    vscode.window.showWarningMessage(
        message,
        'View Details',
        'Apply All Fixes'
    ).then(selection => {
        if (selection === 'View Details') {
            vscode.commands.executeCommand('ai-software-scanner.showSecurityPanel');
        } else if (selection === 'Apply All Fixes') {
            // Apply automated fixes
            applyAllFixes(vulnerabilities, recommendations);
        }
    });
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
        vscode.window.showWarningMessage('Please open a file to see demo recommendations');
        return;
    }

    // Sample recommendations matching your Figma mockup
    const demoRecommendations: Recommendation[] = [
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
        }
    ];

    // Apply decorations to show inline recommendations
    recommendationDecorator.setRecommendations(
        editor.document.uri.toString(),
        demoRecommendations
    );

    // Update sidebar count
    sidebarProvider.updateRecommendations(demoRecommendations.length);

    // Show a sample recommendation panel after a short delay
    setTimeout(() => {
        const sampleRecommendation = {
            line: 61,
            column: 20,
            severity: 'medium',
            type: 'ExpDistribution Security Issue',
            message: 'Potential security vulnerability in probability distribution',
            suggestion: 'Use secure random generation with proper entropy sources',
            currentCode: 'ExpDistribution(mean: fields["mean-duration"].toDouble()),\nExpDistribution(mean: fields["mean-interarrival-time"].toDouble()),',
            fixedCode: 'SecureExpDistribution(mean: fields["mean-duration"].toDouble(), entropy: SecureRandom()),\nSecureExpDistribution(mean: fields["mean-interarrival-time"].toDouble(), entropy: SecureRandom()),',
            explanation: 'Using predictable random distributions can make your application vulnerable to timing attacks and prediction exploits. By using cryptographically secure random sources, you ensure that attackers cannot predict or manipulate the distribution outcomes.'
        };

        RecommendationPanel.createOrShow(vscode.Uri.file(editor.document.fileName), sampleRecommendation);
    }, 1000);

    vscode.window.showInformationMessage(
        '🎨 Demo UI loaded! Check the sidebar and code decorations.',
        'View Details'
    ).then(selection => {
        if (selection === 'View Details') {
            outputChannel.appendLine('\n=== Demo Recommendations ===');
            outputChannel.appendLine(`Found ${demoRecommendations.length} security issues`);
            demoRecommendations.forEach((rec, i) => {
                outputChannel.appendLine(`\n${i + 1}. [${rec.severity.toUpperCase()}] ${rec.type}`);
                outputChannel.appendLine(`   Line ${rec.line}: ${rec.message}`);
                outputChannel.appendLine(`   Fix: ${rec.suggestion}`);
            });
            outputChannel.show();
        }
    });
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
