import * as vscode from 'vscode';

export interface Recommendation {
    line: number;
    column: number;
    endLine?: number;
    endColumn?: number;
    severity: 'low' | 'medium' | 'high' | 'critical';
    message: string;
    suggestion: string;
    type: string;
}

export class RecommendationDecorator {
    private decorationTypes: Map<string, vscode.TextEditorDecorationType> = new Map();
    private activeRecommendations: Map<string, Recommendation[]> = new Map();

    constructor() {
        this.initializeDecorationTypes();
        
        // Update decorations when active editor changes
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor) {
                this.updateDecorations(editor);
            }
        });
    }

    private initializeDecorationTypes() {
        // Critical severity - red underline
        this.decorationTypes.set('critical', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline wavy #ff0000',
            backgroundColor: 'rgba(255, 0, 0, 0.1)',
            gutterIconPath: vscode.Uri.parse('data:image/svg+xml;base64,' + this.createDotSvg('#ff0000')),
            gutterIconSize: 'contain',
            overviewRulerColor: '#ff0000',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
        }));

        // High severity - orange underline
        this.decorationTypes.set('high', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline wavy #ff8800',
            backgroundColor: 'rgba(255, 136, 0, 0.1)',
            gutterIconPath: vscode.Uri.parse('data:image/svg+xml;base64,' + this.createDotSvg('#ff8800')),
            gutterIconSize: 'contain',
            overviewRulerColor: '#ff8800',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
        }));

        // Medium severity - yellow underline
        this.decorationTypes.set('medium', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline wavy #ffcc00',
            backgroundColor: 'rgba(255, 204, 0, 0.05)',
            gutterIconPath: vscode.Uri.parse('data:image/svg+xml;base64,' + this.createDotSvg('#ffcc00')),
            gutterIconSize: 'contain',
            overviewRulerColor: '#ffcc00',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
        }));

        // Low severity - blue underline
        this.decorationTypes.set('low', vscode.window.createTextEditorDecorationType({
            textDecoration: 'underline dotted #0099ff',
            backgroundColor: 'rgba(0, 153, 255, 0.05)',
            gutterIconPath: vscode.Uri.parse('data:image/svg+xml;base64,' + this.createDotSvg('#0099ff')),
            gutterIconSize: 'contain',
            overviewRulerColor: '#0099ff',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
        }));
    }

    private createDotSvg(color: string): string {
        const svg = `<svg width="16" height="16" viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg">
            <circle cx="8" cy="8" r="6" fill="${color}" opacity="0.8"/>
        </svg>`;
        return Buffer.from(svg).toString('base64');
    }

    public setRecommendations(documentUri: string, recommendations: Recommendation[]) {
        this.activeRecommendations.set(documentUri, recommendations);
        
        const editor = vscode.window.activeTextEditor;
        if (editor && editor.document.uri.toString() === documentUri) {
            this.updateDecorations(editor);
        }
    }

    public updateDecorations(editor: vscode.TextEditor) {
        const documentUri = editor.document.uri.toString();
        const recommendations = this.activeRecommendations.get(documentUri) || [];

        // Group recommendations by severity
        const grouped = new Map<string, vscode.DecorationOptions[]>();
        
        recommendations.forEach(rec => {
            if (!grouped.has(rec.severity)) {
                grouped.set(rec.severity, []);
            }

            const startPos = new vscode.Position(rec.line - 1, rec.column - 1);
            const endPos = new vscode.Position(
                rec.endLine ? rec.endLine - 1 : rec.line - 1,
                rec.endColumn ? rec.endColumn - 1 : rec.column + 20
            );

            const decoration: vscode.DecorationOptions = {
                range: new vscode.Range(startPos, endPos),
                hoverMessage: this.createHoverMessage(rec)
            };

            grouped.get(rec.severity)!.push(decoration);
        });

        // Apply decorations for each severity
        ['critical', 'high', 'medium', 'low'].forEach(severity => {
            const decorationType = this.decorationTypes.get(severity);
            const decorations = grouped.get(severity) || [];
            
            if (decorationType) {
                editor.setDecorations(decorationType, decorations);
            }
        });
    }

    private createHoverMessage(rec: Recommendation): vscode.MarkdownString {
        const md = new vscode.MarkdownString();
        md.supportHtml = true;
        md.isTrusted = true;

        // Create severity badge
        const severityColors = {
            critical: '#ff0000',
            high: '#ff8800',
            medium: '#ffcc00',
            low: '#0099ff'
        };

        md.appendMarkdown(`<span style="background-color:${severityColors[rec.severity]}; color:white; padding:2px 6px; border-radius:3px; font-weight:bold; font-size:11px;">${rec.severity.toUpperCase()}</span>\n\n`);
        md.appendMarkdown(`**${rec.type}**\n\n`);
        md.appendMarkdown(`${rec.message}\n\n`);
        md.appendMarkdown(`---\n\n`);
        md.appendMarkdown(`💡 **Recommendation:**\n\n`);
        md.appendMarkdown(`${rec.suggestion}\n\n`);
        
        // Add action buttons using command URIs
        md.appendMarkdown(`[$(check) Accept Fix](command:ai-software-scanner.acceptRecommendation?${encodeURIComponent(JSON.stringify({line: rec.line, type: rec.type}))}) `);
        md.appendMarkdown(`[$(x) Decline](command:ai-software-scanner.declineRecommendation?${encodeURIComponent(JSON.stringify({line: rec.line, type: rec.type}))}) `);
        md.appendMarkdown(`[$(info) Learn More](command:ai-software-scanner.learnMore?${encodeURIComponent(JSON.stringify({type: rec.type}))})`);

        return md;
    }

    public clearDecorations(documentUri: string) {
        this.activeRecommendations.delete(documentUri);
        
        const editor = vscode.window.activeTextEditor;
        if (editor && editor.document.uri.toString() === documentUri) {
            this.decorationTypes.forEach(decorationType => {
                editor.setDecorations(decorationType, []);
            });
        }
    }

    public dispose() {
        this.decorationTypes.forEach(decorationType => {
            decorationType.dispose();
        });
        this.decorationTypes.clear();
        this.activeRecommendations.clear();
    }
}