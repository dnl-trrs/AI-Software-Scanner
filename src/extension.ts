// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
    
    // Use the console to output diagnostic information (console.log) and errors (console.error)
    // This line of code will only be executed once when your extension is activated
    console.log('Congratulations, your extension "ai-software-scanner" is now active!');

    // The command has been defined in the package.json file
    // Now provide the implementation of the command with registerCommand
    // The commandId parameter must match the command field in package.json
    const disposable = vscode.commands.registerCommand('ai-software-scanner.helloWorld', () => {
        // The code you place here will be executed every time your command is executed
        // Display a message box to the user
        vscode.window.showInformationMessage('Hello World from AI Software Scanner!');
    });

    context.subscriptions.push(disposable);

    // Register the scan command
    let scanDisposable = vscode.commands.registerCommand('ai-software-scanner.scanFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No file is open to scan');
            return;
        }

        const document = editor.document;
        const text = document.getText();

        try {
            // Here you would:
            // 1. Send the code to your AI model for analysis
            // 2. Get back security recommendations
            // 3. Display results to user
            
            // Placeholder: Log the text length for now
            console.log(`Scanning ${text.length} characters of code`);
            
            // For now, we'll create a diagnostic collection to show issues
            const diagnostics = vscode.languages.createDiagnosticCollection('security-scan');
            
            // Example diagnostic (you would generate these from AI results)
            const diagnostic = new vscode.Diagnostic(
                new vscode.Range(0, 0, 0, 10),
                'Example security issue found',
                vscode.DiagnosticSeverity.Warning
            );
            
            diagnostics.set(document.uri, [diagnostic]);
            
        } catch (error) {
            vscode.window.showErrorMessage('Error scanning file: ' + error);
        }
    });

    context.subscriptions.push(scanDisposable);
}

// This method is called when your extension is deactivated
export function deactivate() {}