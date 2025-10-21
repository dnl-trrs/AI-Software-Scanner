import * as vscode from 'vscode';
import { SecurityIssue } from '../../scanner';

export class ScanResultsProvider implements vscode.TreeDataProvider<ResultItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<ResultItem | undefined | null | void> = new vscode.EventEmitter<ResultItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<ResultItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private results: Map<string, SecurityIssue[]> = new Map();

    constructor() {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    updateResults(filePath: string, issues: SecurityIssue[]): void {
        this.results.set(filePath, issues);
        this.refresh();
    }

    clearResults(): void {
        this.results.clear();
        this.refresh();
    }

    getTreeItem(element: ResultItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: ResultItem): Thenable<ResultItem[]> {
        if (!element) {
            // Root level - show files with issues
            const items: ResultItem[] = [];
            this.results.forEach((issues, filePath) => {
                const fileItem = new ResultItem(
                    vscode.Uri.file(filePath).fsPath,
                    vscode.TreeItemCollapsibleState.Expanded,
                    {
                        command: 'vscode.open',
                        title: 'Open File',
                        arguments: [vscode.Uri.file(filePath)]
                    }
                );
                fileItem.description = `${issues.length} issue${issues.length === 1 ? '' : 's'}`;
                fileItem.contextValue = 'file';
                items.push(fileItem);
            });
            return Promise.resolve(items);
        } else if (element.contextValue === 'file') {
            // File level - show issues
            const issues = this.results.get(element.resourceUri?.fsPath || '') || [];
            return Promise.resolve(
                issues.map(issue => {
                    const issueItem = new ResultItem(
                        `${issue.type} (Line ${issue.line})`,
                        vscode.TreeItemCollapsibleState.None
                    );
                    issueItem.description = issue.message;
                    issueItem.iconPath = this.getIconForSeverity(issue.severity);
                    issueItem.contextValue = 'issue';
                    issueItem.command = {
                        command: 'aiSoftwareScanner.showIssueDetails',
                        title: 'Show Issue Details',
                        arguments: [issue]
                    };
                    return issueItem;
                })
            );
        }
        return Promise.resolve([]);
    }

    private getIconForSeverity(severity: string): vscode.ThemeIcon {
        switch (severity.toLowerCase()) {
            case 'error':
                return new vscode.ThemeIcon('error');
            case 'warning':
                return new vscode.ThemeIcon('warning');
            default:
                return new vscode.ThemeIcon('info');
        }
    }
}

export class ResultItem extends vscode.TreeItem {
    constructor(
        label: string,
        collapsibleState: vscode.TreeItemCollapsibleState,
        command?: vscode.Command
    ) {
        super(label, collapsibleState);
        if (command) {
            this.command = command;
        }
    }
}