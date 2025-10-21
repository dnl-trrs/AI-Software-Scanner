/**
 * Scanner Module
 * 
 * This module handles the core scanning functionality including:
 * - File parsing and analysis
 * - Static code analysis
 * - Security pattern matching
 * - Integration with AI analysis
 */

import * as vscode from 'vscode';
import { AIAnalysisResponse } from '../ai';

export interface ScanOptions {
  includeAI: boolean;
  scanScope: 'file' | 'workspace';
  languages: string[];
}

export interface ScanResult {
  filePath: string;
  issues: SecurityIssue[];
  aiAnalysis?: AIAnalysisResponse;
  scanTime: number;
}

export interface SecurityPattern {
  id: string;
  type: string;
  regex: RegExp;
  severity: 'info' | 'warning' | 'error';
  message: string;
}

export interface SecurityIssue {
  id: string;
  type: string;
  severity: 'info' | 'warning' | 'error';
  message: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  source: 'static' | 'ai';
  cwe?: string;
  description?: string;
  remediation?: string;
}

export class CodeScanner {
  private patterns: Map<string, SecurityPattern[]>;

  constructor() {
    this.patterns = this.initializePatterns();
  }

  private initializePatterns(): Map<string, SecurityPattern[]> {
    const patterns = new Map<string, SecurityPattern[]>();

    // JavaScript/TypeScript patterns
    const jsPatterns: SecurityPattern[] = [
      {
        id: 'JS001',
        type: 'eval-usage',
        regex: /\beval\s*\(/g,
        severity: 'error',
        message: 'Use of eval() is discouraged as it can lead to code injection vulnerabilities'
      },
      {
        id: 'JS002',
        type: 'insecure-random',
        regex: /Math\.random\s*\(/g,
        severity: 'warning',
        message: 'Math.random() is not cryptographically secure. Use crypto.getRandomValues() for security-sensitive operations'
      },
      {
        id: 'JS003',
        type: 'innerHTML-usage',
        regex: /\.innerHTML\s*=/g,
        severity: 'warning',
        message: 'Use of innerHTML can lead to XSS vulnerabilities. Consider using textContent or sanitize input'
      },
      {
        id: 'JS004',
        type: 'prototype-pollution',
        regex: /Object\.assign\s*\(\s*{}\s*,/g,
        severity: 'warning',
        message: 'Potential prototype pollution vulnerability. Consider using Object.create(null) or a deep clone'
      }
    ];

    // Set patterns for both JavaScript and TypeScript
    patterns.set('javascript', jsPatterns);
    patterns.set('typescript', jsPatterns);

    // Python patterns
    const pythonPatterns: SecurityPattern[] = [
      {
        id: 'PY001',
        type: 'exec-usage',
        regex: /\bexec\s*\(/g,
        severity: 'error',
        message: 'Use of exec() is dangerous as it can lead to code injection vulnerabilities'
      },
      {
        id: 'PY002',
        type: 'shell-injection',
        regex: /\b(?:os\.system|subprocess\.call|subprocess\.Popen)\s*\(/g,
        severity: 'warning',
        message: 'Shell command execution detected. Ensure proper input sanitization'
      },
      {
        id: 'PY003',
        type: 'sql-injection',
        regex: /\.execute\s*\(\s*(?:['"]\s*[\w\s]+\s*['"]?\s*%|\+|\.format)/g,
        severity: 'error',
        message: 'Potential SQL injection vulnerability. Use parameterized queries'
      }
    ];

    patterns.set('python', pythonPatterns);

    // Java patterns
    const javaPatterns: SecurityPattern[] = [
      {
        id: 'JV001',
        type: 'command-injection',
        regex: /Runtime\.getRuntime\(\)\.exec\(/g,
        severity: 'error',
        message: 'Command injection vulnerability detected. Validate and sanitize input before execution'
      },
      {
        id: 'JV002',
        type: 'sql-injection',
        regex: /(?:prepareStatement|createQuery|createNativeQuery)\s*\(\s*.*\+\s*.*\)/g,
        severity: 'error',
        message: 'Potential SQL injection vulnerability. Use parameterized queries with prepared statements'
      },
      {
        id: 'JV003',
        type: 'insecure-random',
        regex: /new\s+Random\(/g,
        severity: 'warning',
        message: 'Using java.util.Random is not cryptographically secure. Use java.security.SecureRandom for security-sensitive operations'
      },
      {
        id: 'JV004',
        type: 'xxe',
        regex: /DocumentBuilderFactory\.newInstance\(\)/g,
        severity: 'warning',
        message: 'XML parsing may be vulnerable to XXE attacks. Set feature "http://apache.org/xml/features/disallow-doctype-decl" to true'
      },
      {
        id: 'JV005',
        type: 'path-traversal',
        regex: /new\s+File\([^)]*\.\.[^)]*\)/g,
        severity: 'error',
        message: 'Potential path traversal vulnerability. Validate and sanitize file paths'
      }
    ];

    patterns.set('java', javaPatterns);

    // C/C++ patterns
    const cppPatterns: SecurityPattern[] = [
      {
        id: 'CPP001',
        type: 'buffer-overflow',
        regex: /\b(?:strcpy|strcat|sprintf|vsprintf|gets)\s*\(/g,
        severity: 'error',
        message: 'Using unsafe string function. Use strncpy, strncat, snprintf, or fgets instead'
      },
      {
        id: 'CPP002',
        type: 'format-string',
        regex: /printf\s*\([^"]*[%][^"]*"\s*,/g,
        severity: 'error',
        message: 'Potential format string vulnerability. Use constant format strings'
      },
      {
        id: 'CPP003',
        type: 'memory-leak',
        regex: /\bmalloc\b|\bnew\b(?!\[)/g,
        severity: 'warning',
        message: 'Memory allocation detected. Ensure proper deallocation to prevent memory leaks'
      },
      {
        id: 'CPP004',
        type: 'null-pointer',
        regex: /\-\>(?!\s*[{])/g,
        severity: 'warning',
        message: 'Potential null pointer dereference. Add null check before dereferencing'
      },
      {
        id: 'CPP005',
        type: 'integer-overflow',
        regex: /\+=|\-=|\*=|\/=|\+\+|\-\-/g,
        severity: 'info',
        message: 'Check for potential integer overflow in arithmetic operations'
      }
    ];

    patterns.set('cpp', cppPatterns);
    patterns.set('c', cppPatterns);

    // C# patterns
    const csharpPatterns: SecurityPattern[] = [
      {
        id: 'CS001',
        type: 'sql-injection',
        regex: /SqlCommand\([^)]*\+/g,
        severity: 'error',
        message: 'Potential SQL injection vulnerability. Use parameterized queries with SqlParameter'
      },
      {
        id: 'CS002',
        type: 'xss',
        regex: /Response\.Write\(/g,
        severity: 'warning',
        message: 'Potential XSS vulnerability. Encode output with HttpUtility.HtmlEncode'
      },
      {
        id: 'CS003',
        type: 'insecure-deserialize',
        regex: /BinaryFormatter\.Deserialize|JsonSerializer\.Deserialize/g,
        severity: 'warning',
        message: 'Unsafe deserialization detected. Validate input before deserializing'
      },
      {
        id: 'CS004',
        type: 'path-traversal',
        regex: /Path\.Combine\([^)]+\)/g,
        severity: 'warning',
        message: 'Check for path traversal vulnerabilities in file operations'
      },
      {
        id: 'CS005',
        type: 'crypto',
        regex: /new\s+MD5CryptoServiceProvider\(\)|new\s+SHA1CryptoServiceProvider\(\)/g,
        severity: 'error',
        message: 'Using weak cryptographic algorithm. Use SHA256 or stronger algorithms'
      }
    ];

    patterns.set('csharp', csharpPatterns);

    return patterns;
  }

  async scanFile(document: vscode.TextDocument, options: ScanOptions): Promise<ScanResult> {
    const startTime = Date.now();
    const issues: SecurityIssue[] = [];
    const text = document.getText();
    const languageId = document.languageId;

    // Check if the language is supported and enabled in options
    if (!options.languages.includes(languageId)) {
      return {
        filePath: document.uri.fsPath,
        issues: [],
        scanTime: 0
      };
    }

    // Get patterns for the current language
    const languagePatterns = this.patterns.get(languageId) || [];

    // Scan for each pattern
    for (const pattern of languagePatterns) {
      let match;
      pattern.regex.lastIndex = 0; // Reset regex state for global patterns
      
      while ((match = pattern.regex.exec(text)) !== null) {
        const position = document.positionAt(match.index);
        const endPosition = document.positionAt(match.index + match[0].length);

        issues.push({
          id: pattern.id,
          type: pattern.type,
          severity: pattern.severity,
          message: pattern.message,
          line: position.line,
          column: position.character,
          endLine: endPosition.line,
          endColumn: endPosition.character,
          source: 'static'
        });
      }
    }

    // Get the scan time
    const scanTime = Date.now() - startTime;

    // Return the scan result
    return {
      filePath: document.uri.fsPath,
      issues,
      scanTime
    };
  }

  /**
   * Scans all supported files in the workspace
   */
  async scanWorkspace(workspaceFolders: readonly vscode.WorkspaceFolder[], options: ScanOptions): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    const startTime = Date.now();

    // Get files with supported extensions
    const filePatterns = options.languages.map(lang => `**/*.{${this.getFileExtensions(lang)}}`);
    
    for (const folder of workspaceFolders) {
      for (const pattern of filePatterns) {
        const files = await vscode.workspace.findFiles(
          new vscode.RelativePattern(folder, pattern),
          '**/node_modules/**'
        );

        // Process each file
        for (const file of files) {
          try {
            const document = await vscode.workspace.openTextDocument(file);
            const result = await this.scanFile(document, options);
            if (result.issues.length > 0) {
              results.push(result);
            }
          } catch (error) {
            console.error(`Error scanning file ${file.fsPath}:`, error);
          }
        }
      }
    }

    // Update scan time for all results
    const totalTime = Date.now() - startTime;
    results.forEach(result => result.scanTime = totalTime);

    return results;
  }

  /**
   * Gets the file extensions for a given language
   */
  private getFileExtensions(languageId: string): string {
    switch (languageId) {
      case 'javascript':
        return 'js,jsx,mjs';
      case 'typescript':
        return 'ts,tsx';
      case 'python':
        return 'py';
      case 'java':
        return 'java';
      case 'cpp':
        return 'cpp,cc,cxx,h,hpp,hxx';
      case 'c':
        return 'c,h';
      case 'csharp':
        return 'cs';
      default:
        return '';
    }
  }
}