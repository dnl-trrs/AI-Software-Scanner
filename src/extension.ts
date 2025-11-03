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
// Track line adjustments for each file after fixes are applied
let lineAdjustments: Map<string, number[]> = new Map();

// Track scanned files to prevent duplicate scans
let scannedFiles = new Set<string>();
let fileHashes = new Map<string, string>();
let isScanning = false;

// Helper function to apply fix to a specific editor
async function applyFixToEditor(editor: vscode.TextEditor, vulnerability: any, fix: string) {
    const fileName = editor.document.fileName;
    const originalLineCount = editor.document.lineCount;
    
    await editor.edit((editBuilder) => {
        // Apply line adjustments from previous fixes in this file
        let adjustedLine = vulnerability.line;
        const fileAdjustments = lineAdjustments.get(fileName) || [];
        for (const adjustment of fileAdjustments) {
            if (adjustment < vulnerability.line) {
                adjustedLine += adjustment;
            }
        }
        
        const startLine = adjustedLine - 1; // Convert to 0-based
        
        // Clean the fix string - remove explanatory comments and extract just the code
        let cleanedFix = extractActualCode(fix);
        
        // Get the original line and its indentation
        const originalLine = editor.document.lineAt(startLine).text;
        const originalIndentMatch = originalLine.match(/^(\s*)/);
        const originalIndentation = originalIndentMatch ? originalIndentMatch[1] : '';
        
        // Determine how many lines to replace
        let linesToReplace = 1;
        if (vulnerability.endLine) {
            linesToReplace = vulnerability.endLine - vulnerability.line + 1;
        } else if (vulnerability.code) {
            // Count actual lines in the vulnerable code
            const codeLines = vulnerability.code.split('\n');
            linesToReplace = codeLines.length;
        }
        
        // Calculate the actual range to replace
        let endLine = Math.min(startLine + linesToReplace - 1, editor.document.lineCount - 1);
        
        // Split the fix into lines and process each one
        const fixLines = cleanedFix.split('\n');
        
        // Smart indentation: analyze the fix to maintain structure
        const processedLines: string[] = [];
        let baseIndentLevel = originalIndentation.length;
        
        for (let i = 0; i < fixLines.length; i++) {
            const line = fixLines[i];
            const trimmedLine = line.trim();
            
            if (trimmedLine.length === 0) {
                // Keep empty lines
                processedLines.push('');
                continue;
            }
            
            // Detect the indentation level from the original fix
            const fixLineIndentMatch = line.match(/^(\s*)/);
            const fixLineIndent = fixLineIndentMatch ? fixLineIndentMatch[1].length : 0;
            
            // Calculate relative indentation from the first non-empty line
            if (i === 0) {
                // First line uses the original indentation
                processedLines.push(originalIndentation + trimmedLine);
            } else {
                // For subsequent lines, check if they should be indented more
                // Look for block indicators in the previous line
                const prevLine = processedLines[processedLines.length - 1];
                const prevTrimmed = prevLine.trim();
                
                // Check if previous line opens a block
                const opensBlock = prevTrimmed.endsWith('{') || 
                                  prevTrimmed.endsWith(':') || 
                                  prevTrimmed.includes('=>') ||
                                  prevTrimmed.startsWith('if ') ||
                                  prevTrimmed.startsWith('for ') ||
                                  prevTrimmed.startsWith('while ');
                
                // Check if current line closes a block
                const closesBlock = trimmedLine.startsWith('}') || 
                                   trimmedLine.startsWith(')');
                
                // Check if this line is a continuation (e.g., chained methods)
                const isContinuation = trimmedLine.startsWith('.') || 
                                      prevTrimmed.endsWith(',') ||
                                      prevTrimmed.endsWith('+') ||
                                      prevTrimmed.endsWith('||') ||
                                      prevTrimmed.endsWith('&&');
                
                let indentToUse = originalIndentation;
                
                if (closesBlock) {
                    // Same level as original
                    indentToUse = originalIndentation;
                } else if (opensBlock || isContinuation) {
                    // Add one level of indentation
                    const indentUnit = originalIndentation.includes('\t') ? '\t' : '    ';
                    indentToUse = originalIndentation + indentUnit;
                } else {
                    // Check relative indentation in the original fix
                    if (fixLineIndent > 0 && i > 0) {
                        // This line was indented in the fix, maintain relative indent
                        const indentUnit = originalIndentation.includes('\t') ? '\t' : '    ';
                        indentToUse = originalIndentation + indentUnit;
                    } else {
                        indentToUse = originalIndentation;
                    }
                }
                
                processedLines.push(indentToUse + trimmedLine);
            }
        }
        
        const processedFix = processedLines.join('\n');
        
        const range = new vscode.Range(
            startLine, 0,
            endLine, editor.document.lineAt(endLine).text.length
        );
        
        // Replace the vulnerable code with the fix
        editBuilder.replace(range, processedFix);
    });
    
    // Calculate line adjustment after the edit
    const newLineCount = editor.document.lineCount;
    const lineChange = newLineCount - originalLineCount;
    
    // Store the adjustment for future fixes
    if (lineChange !== 0) {
        if (!lineAdjustments.has(fileName)) {
            lineAdjustments.set(fileName, []);
        }
        lineAdjustments.get(fileName)!.push(lineChange);
        
        // Update remaining recommendations with new line numbers
        updateRecommendationLineNumbers(fileName, vulnerability.line, lineChange);
    }
    
    // Reveal the fixed line
    const revealRange = new vscode.Range(vulnerability.line - 1, 0, vulnerability.line - 1, 0);
    editor.revealRange(revealRange, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
}

// Helper function to extract actual code from fix suggestions
function extractActualCode(fix: string): string {
    // Remove common explanation patterns
    let cleaned = fix;
    
    // Remove lines that are clearly comments or explanations
    const lines = cleaned.split('\n');
    const codeLines = lines.filter(line => {
        const trimmed = line.trim();
        // Skip lines that are clearly explanatory
        if (trimmed.startsWith('//') && (
            trimmed.includes('Use ') ||
            trimmed.includes('Instead of') ||
            trimmed.includes('Replace ') ||
            trimmed.includes('Change ') ||
            trimmed.includes('Move ') ||
            trimmed.includes('Add ') ||
            trimmed.includes('Create ') ||
            trimmed.includes('Don\'t ') ||
            trimmed.includes('GOOD:') ||
            trimmed.includes('BAD:') ||
            trimmed.includes('Example:') ||
            trimmed.includes('Note:')
        )) {
            return false;
        }
        // Skip numbered instructions
        if (/^\d+\.\s/.test(trimmed)) {
            return false;
        }
        // Skip import suggestions that are explanatory
        if (trimmed.startsWith('import') && trimmed.includes('//')) {
            // Keep the import but remove the comment
            return true;
        }
        return true;
    });
    
    // Join the filtered lines
    cleaned = codeLines.join('\n');
    
    // Remove inline comments that are explanatory
    cleaned = cleaned.replace(/\/\/.*?(instead|rather than|not|don't|avoid|use|replace).*/gi, '');
    
    // Extract code blocks if the fix contains markdown-style code blocks
    const codeBlockMatch = cleaned.match(/```[\w]*\n([\s\S]*?)```/);
    if (codeBlockMatch) {
        cleaned = codeBlockMatch[1];
    }
    
    // Remove require/import statements that are followed by config examples
    cleaned = cleaned.replace(/require\(['"]dotenv['"]\)\.config\(\);[\s\S]*?(?=\n[^\s])/g, '');
    
    // Clean up any remaining explanation text
    const finalLines = cleaned.split('\n').map(line => {
        // Remove inline comments at the end of lines
        return line.replace(/\s*\/\/\s*(Safe|Fixed|Secure|Better|Correct|This is).*/i, '');
    }).filter(line => line.trim().length > 0);
    
    return finalLines.join('\n');
}

// Helper function to update line numbers in remaining recommendations
function updateRecommendationLineNumbers(fileName: string, fixedLine: number, lineChange: number) {
    currentRecommendations = currentRecommendations.map(rec => {
        if (rec.vulnerability && rec.vulnerability.file === fileName) {
            // Only update if the vulnerability is after the fixed line
            if (rec.vulnerability.line > fixedLine) {
                return {
                    ...rec,
                    vulnerability: {
                        ...rec.vulnerability,
                        line: rec.vulnerability.line + lineChange,
                        endLine: rec.vulnerability.endLine ? rec.vulnerability.endLine + lineChange : undefined
                    }
                };
            }
        }
        return rec;
    });
    
    // If the recommendation panel is open, update it
    if (RecommendationPanel.currentPanel) {
        RecommendationPanel.currentPanel.updateRecommendations(currentRecommendations);
    }
}

// Helper function to update UI after fix is applied
function updateAfterFix(vulnerability: any) {
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
}

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
            // Get the vulnerability and fix from the data
            const { vulnerability, fix } = data;
            
            if (!vulnerability || !fix) {
                vscode.window.showErrorMessage('Invalid fix data');
                return;
            }
            
            let targetEditor: vscode.TextEditor | undefined;
            
            // First, try to find the editor with the vulnerable file
            if (vulnerability.file) {
                // Try to find if the file is already open
                const targetUri = vscode.Uri.file(vulnerability.file);
                targetEditor = vscode.window.visibleTextEditors.find(
                    editor => editor.document.uri.fsPath === targetUri.fsPath
                );
                
                if (!targetEditor) {
                    // File not open, open it
                    const document = await vscode.workspace.openTextDocument(targetUri);
                    targetEditor = await vscode.window.showTextDocument(document, vscode.ViewColumn.One);
                }
            } else {
                // No specific file specified, try to get the active editor
                targetEditor = vscode.window.activeTextEditor;
                
                // If no active editor, try to get the first visible editor
                if (!targetEditor && vscode.window.visibleTextEditors.length > 0) {
                    targetEditor = vscode.window.visibleTextEditors[0];
                    await vscode.window.showTextDocument(targetEditor.document, targetEditor.viewColumn);
                }
            }
            
            if (!targetEditor) {
                // Last resort: try to open a file from the workspace
                const files = await vscode.workspace.findFiles('**/*.{js,ts,jsx,tsx}', '**/node_modules/**', 1);
                if (files.length > 0) {
                    const document = await vscode.workspace.openTextDocument(files[0]);
                    targetEditor = await vscode.window.showTextDocument(document, vscode.ViewColumn.One);
                } else {
                    vscode.window.showWarningMessage('No editor available to apply the fix. Please open a file first.');
                    return;
                }
            }
            
            // Apply the fix to the target editor
            await applyFixToEditor(targetEditor, vulnerability, fix);
            
            acceptedCount++;
            updateAfterFix(vulnerability);
            
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

    // Auto-scan listeners - DISABLED by default
    // Only scan when explicitly triggered from sidebar button
    const onSaveListener = vscode.workspace.onDidSaveTextDocument(async (document) => {
        // Disabled - only scan via sidebar button
        // Keeping listener structure for potential future use
    });

    // Auto-scan on file open - DISABLED
    const onOpenListener = vscode.window.onDidChangeActiveTextEditor(async (editor) => {
        // Disabled - only scan via sidebar button
        // Keeping listener structure for potential future use
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
    
    // Clear line adjustments for this file when starting a new scan
    lineAdjustments.delete(document.fileName);
    
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
                    automaticFix: vuln.automaticFix,
                    // Include the file path for proper fix application
                    file: document.fileName
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
