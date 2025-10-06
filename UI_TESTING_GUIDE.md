# AI Software Scanner - UI Testing Guide

## How to Test the New UI

### Step 1: Open the Project in VS Code
```bash
code /Users/dnl/Documents/GitHub/AI-Software-Scanner
```

### Step 2: Launch the Extension Development Host
1. Press **F5** (or Run > Start Debugging from the menu)
2. This will open a **new VS Code window** titled "[Extension Development Host]"
3. The extension is loaded in this new window only

### Step 3: In the Extension Development Host Window

#### Option A: Use Command Palette
1. Press `Cmd+Shift+P` (Mac) to open the command palette
2. Type any of these commands:
   - `AI Security: Demo UI` - Shows the demo with sample recommendations
   - `AI Security: Scan Current File` - Scans the current file
   - `AI Security: Show Security Panel` - Shows the security panel

#### Option B: Use Keyboard Shortcuts
- `Shift+Cmd+S` - Scan current file

#### Option C: Right-Click Menu
- Right-click in any JavaScript/TypeScript file
- Select "Scan Current File for Security Issues"

### Step 4: View the UI Components

1. **Sidebar Panel**
   - Look in the Explorer sidebar (left side)
   - You should see an "AI Scanner" section
   - Click on it to expand and see the control buttons

2. **Open the Demo File**
   ```bash
   # In the Extension Development Host window, open:
   /Users/dnl/Documents/GitHub/AI-Software-Scanner/demo-file.js
   ```

3. **Run the Demo**
   - With demo-file.js open, press `Cmd+Shift+P`
   - Type: `AI Security: Demo UI`
   - Press Enter

### What You Should See

1. **Sidebar Updates**
   - The recommendation count changes to "2"
   - Buttons are interactive

2. **Inline Code Decorations**
   - Lines with issues get colored underlines
   - Hover over underlined code to see tooltips

3. **Recommendation Panel**
   - A panel opens showing detailed recommendation
   - Has Accept/Decline buttons
   - Shows before/after code comparison

### Troubleshooting

**If commands don't appear:**
1. Make sure you're in the Extension Development Host window (not the original)
2. Try reloading the window: `Cmd+R` in the Extension Development Host
3. Check the Debug Console in the original VS Code window for errors

**If the sidebar doesn't appear:**
1. Click View > Explorer (or `Cmd+Shift+E`)
2. Look for "AI Scanner" in the sidebar
3. You may need to collapse/expand other sections

**To see console logs:**
- In the Extension Development Host window: View > Output
- Select "AI Software Security Scanner" from the dropdown

### Quick Demo Commands

```bash
# After opening the Extension Development Host:
# 1. Open the demo file
# 2. Run command palette (Cmd+Shift+P)
# 3. Type and run: AI Security: Demo UI
```

### Files Created for UI

- `src/ui/SidebarProvider.ts` - Sidebar webview panel
- `src/ui/RecommendationDecorator.ts` - Inline code decorations
- `src/ui/RecommendationPanel.ts` - Detailed recommendation modal
- `demo-file.js` - Sample file with security issues for testing

## Development Workflow

1. Make changes to the TypeScript files
2. Run `npm run compile` in terminal
3. Press `Cmd+R` in the Extension Development Host to reload
4. Test your changes

## Next Steps

Once you've seen the UI demo, you can:
1. Connect real scanning logic to the UI
2. Customize the styles and colors
3. Add more interactive features
4. Implement the actual security scanning algorithms