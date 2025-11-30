# AI Software Security Scanner - Installation Guide

## Prerequisites

Before installing the AI Software Security Scanner extension, ensure you have the following installed on your system:

- **Node.js** (v14 or higher) - [Download here](https://nodejs.org/)
- **npm** (comes with Node.js)
- **VS Code** (v1.60 or higher) - [Download here](https://code.visualstudio.com/)

To verify you have Node.js and npm installed, run these commands in your terminal:

```bash
node --version
npm --version
```

## Installation Steps

### Step 1: Extract the Extension Files

1. Extract the `AI-Software-Scanner.zip` file to a location on your computer
2. Open a terminal/command prompt and navigate to the extracted folder:

```bash
cd path/to/AI-Software-Scanner
```

### Step 2: Install Dependencies

Install the required npm packages:

```bash
npm install
```

This will download all necessary dependencies and may take a few minutes.

### Step 3: Compile TypeScript

Compile the TypeScript source code to JavaScript:

```bash
npm run compile
```

If compilation is successful, you should see no errors in the terminal.

### Step 4: Package the Extension

Package the extension as a `.vsix` file:

```bash
npm run package
```

This will create a `.vsix` file in the project root directory (e.g., `ai-software-scanner-1.0.0.vsix`).

### Step 5: Install in VS Code

You have two options to install the extension:

**Option A: Using the Command Line**

```bash
code --install-extension ai-software-scanner-1.0.0.vsix
```

Replace `ai-software-scanner-1.0.0.vsix` with the actual filename if the version number differs.

**Option B: Using VS Code UI**

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X / Cmd+Shift+X)
3. Click the three dots menu (⋯) at the top of the Extensions panel
4. Select "Install from VSIX..."
5. Navigate to and select the `.vsix` file you created in Step 4

### Step 6: Configure OpenAI API Key

1. Open VS Code Settings (File → Preferences → Settings, or Ctrl+,)
2. Search for "aiSecurityScanner"
3. Enter your OpenAI API Key in the `OpenAI API Key` setting
4. Alternatively, create a `.env` file in your workspace root with:

```
OPENAI_API_KEY=your-api-key-here
```

To get an OpenAI API key:
- Visit https://platform.openai.com/
- Sign up or log in to your account
- Navigate to API Keys section
- Create a new API key

### Step 7: Reload VS Code

Reload VS Code for the extension to take effect:
- Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
- Type "Developer: Reload Window"
- Press Enter

## Verification

To verify the extension is installed correctly:

1. Look for the **"🛡️ Security"** icon in the VS Code status bar (bottom right)
2. Open a JavaScript, TypeScript, Python, or other supported language file
3. Click the Security icon or use the sidebar to run a scan

## Troubleshooting

### Extension Not Appearing

- Ensure VS Code was reloaded after installation
- Check that the `.vsix` file was created successfully
- Try restarting VS Code completely

### "OpenAI API Key not configured" Warning

- Verify your API key is correctly entered in settings
- Check that your `.env` file (if used) is in the workspace root
- Restart VS Code to reload configuration

### Scan Fails or Shows No Results

- Ensure your OpenAI API key is valid and has available credits
- Check your internet connection
- Review the Output channel: View → Output → "Security Scanner"

### npm install Fails

- Ensure Node.js is properly installed: `node --version`
- Clear npm cache: `npm cache clean --force`
- Delete `node_modules` folder and `package-lock.json`, then try `npm install` again

## Supported Languages

The extension can analyze code in:
- JavaScript / TypeScript
- Python
- Java
- Go
- Ruby
- PHP
- C#
- C++
- C

## Uninstallation

To uninstall the extension:

1. Open VS Code Extensions (Ctrl+Shift+X)
2. Search for "AI Software Security Scanner"
3. Click the gear icon and select "Uninstall"

Or from command line:

```bash
code --uninstall-extension daniel.ai-software-scanner
```

## Getting Help

- Check the Output channel (View → Output → "Security Scanner") for error messages
- Review vulnerability details in the sidebar panel
- Consult the educational content provided for each detected vulnerability

## Support

For issues, feature requests, or questions, please refer to the project documentation or contact support.

---

**Happy secure coding! 🔒**
