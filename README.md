# Markdown to HTML

A Streamlit-based Markdown to standalone HTML converter optimized for statistical reports and technical documentation.

Currently deployed at: https://mdtohtml.streamlit.app/ 

## Overview

md_to_html.py converts Markdown documents into fully self-contained, offline HTML files with embedded JavaScript libraries. Perfect for data scientists, statisticians, and technical writers who need to create professional reports with code blocks, mathematical equations, and rich formatting.

All generated HTML files are completely standalone - no external dependencies, no internet connection required to view.

## Features

### Core Functionality
- **Standalone HTML Generation** - Creates completely self-contained HTML files with all JavaScript embedded
- **Security First** - Uses DOMPurify for XSS protection and implements path traversal prevention
- **Responsive Design** - Mobile-friendly layouts that work on all screen sizes
- **Dark/Light Theme Toggle** - Automatic theme switching with localStorage persistence

### Code and Documentation
- **Syntax Highlighting** - Support for Python, R, Stata, JavaScript, SQL, and 100+ languages via Highlight.js
- **Output Block Styling** - Distinct visual styling for console output blocks (use \`\`\`output fence)
- **Line Numbers** - Optional line numbers on code blocks (automatically skips output blocks)
- **Copy-to-Clipboard** - One-click copy buttons on all code blocks
- **Math Rendering** - Inline ($...$) and display ($$...$$) LaTeX equations via KaTeX

### Navigation and Organization
- **Table of Contents** - Auto-generated ToC with multiple placement options (top, sidebar, or none)
- **Collapsible Sections** - Make H2/H3 sections collapsible with toggle indicators
- **Back to Top Links** - Navigate large documents easily
- **In-Page Search** - Real-time search with highlighting and match counter
- **Heading Anchors** - GitHub-style # links on all headings for direct linking
- **Labeled Section Dividers** - Enhanced horizontal rules with centered labels

### Presentation and Styling
- **Theme Presets** - Five built-in themes: Default, GitHub, Academic, Minimal, and Dark
- **Font Size Control** - Adjustable base font size (90%, 100%, 110%, 125%)
- **Content Width Control** - Choose from Narrow (700px), Normal (900px), Wide (1200px), or Full (95vw)
- **Wide Table Support** - Automatic horizontal scrolling for tables that exceed content width
- **Print Optimized** - Special print styles for clean paper output

### Accessibility
- ARIA labels and roles for screen readers
- Keyboard navigation support (Enter/Space to toggle collapsible sections)
- Skip to content link
- Proper heading hierarchy
- Focus indicators

## Installation

### Requirements
- Python 3.8 or higher
- Streamlit

### Setup

```bash
# Clone or download the repository
git clone https://github.com/yourusername/md_to_html.git
cd md_to_html

# Install Streamlit
pip install streamlit

# Vendor libraries are already included in the vendor/ directory:
# - marked.umd.min.js (Markdown parser)
# - purify.min.js (XSS sanitizer)
# - highlight.min.js (Syntax highlighting)
# - katex.min.js (Math rendering)
# - katex.min.css (Math rendering styles)
```

## Usage

### Starting the Application

```bash
streamlit run md_to_html.py
```

This will open your default web browser to http://localhost:8501

### Basic Workflow

1. **Upload or Paste Markdown**
   - Upload a .md or .markdown file using the file uploader
   - OR paste your Markdown content directly into the text area

2. **Configure Options**

   **Theme and Appearance:**
   - Output Theme: Default, GitHub, Academic, Minimal, or Dark
   - Base Font Size: Small (90%), Normal (100%), Large (110%), or X-Large (125%)
   - Content Width: Narrow (700px), Normal (900px), Wide (1200px), or Full (95vw)
   - In-page search: Toggle to enable/disable search functionality

   **Document Structure:**
   - ToC Placement: Top (inline), Sidebar (collapsible), or None
   - ToC Heading Levels: H2 only, H2-H3, or H2-H3-H4
   - Collapsible Sections: None, H2, or H2+H3
   - Start Collapsed: Toggle to start with sections collapsed
   - Back to Top: Add navigation links at end of each H2 section

   **Code and Math:**
   - Syntax Highlighting: Enable color syntax highlighting for code blocks
   - Syntax Theme: github-light, github-dark, monokai, or atom-one-dark
   - Line Numbers: Show line numbers on left side of code blocks
   - Math/LaTeX Rendering: Enable KaTeX rendering for $...$ and $$...$$ equations

3. **Build HTML**
   - Click the "Build HTML" button
   - Preview appears in the right panel
   - Click "Download offline HTML" to save the file

## Configuration Details

### Theme Presets

- **Default**: Clean, modern theme with blue links and neutral colors
- **GitHub**: Matches GitHub's markdown styling with GitHub-style colors
- **Academic**: Serif fonts (Georgia) with increased line height, optimized for reading
- **Minimal**: Minimalist black and white design with subtle accents
- **Dark**: Dark mode theme with carefully chosen contrast colors

All themes include dark mode variants (via the toggle button in generated HTML).

### Syntax Highlighting Themes

- **github-light**: Light theme matching GitHub's code blocks
- **github-dark**: Dark theme matching GitHub Dark
- **monokai**: Popular dark theme with vibrant colors
- **atom-one-dark**: Atom editor's One Dark theme

### Table of Contents Modes

- **Top**: Inline ToC at the top of the document, always visible
- **Sidebar**: Collapsible sidebar that slides in from the left, with backdrop overlay
- **None**: No table of contents generated

### Content Width Options

- **Narrow (700px)**: Best for text-heavy documents, easier to read
- **Normal (900px)**: Default, balanced for most content
- **Wide (1200px)**: Better for wide code blocks and tables
- **Full (95vw)**: Maximum width, uses 95% of viewport width

The Academic theme is optimized for 700-800px width for improved readability.

## Output Characteristics

### File Size

Generated HTML files are self-contained and include all vendor libraries:

- **Minimal** (no highlighting, no math): ~70-80 KB
- **With syntax highlighting** (no math): ~200-210 KB
- **With math** (no highlighting): ~380-390 KB
- **Full features** (highlighting + math): ~500-510 KB

The majority of file size comes from embedded vendor libraries:
- KaTeX: ~300 KB (277 KB JS + 23 KB CSS)
- Highlight.js: ~122 KB
- Marked.js: ~39 KB
- DOMPurify: ~23 KB

### Browser Compatibility

Generated HTML works in:
- Modern Chrome/Edge (Chromium)
- Firefox 78+
- Safari 14+
- Any browser supporting ES6 JavaScript

Graceful degradation:
- If JavaScript disabled: Raw markdown visible in script tag
- If clipboard API unavailable: Copy buttons use fallback execCommand
- If vendor library fails: Error caught, rest of features continue

### Security

All generated HTML includes:
- XSS protection via DOMPurify sanitization
- No inline event handlers (CSP compatible)
- No eval() or Function() constructors
- Escaped HTML in user-controlled content
- Path traversal prevention in file operations

## Known Limitations

1. **File Size**: Full-featured HTML files are ~500 KB due to embedded libraries
   - Mitigation: Disable features you don't need to reduce size
   - Minimal build is only ~70 KB

2. **JavaScript Required**: Generated HTML requires JavaScript to render
   - Content is stored in a script tag and processed client-side
   - No server-side rendering

3. **No CLI**: Web interface only (Streamlit required)
   - All configuration done through the UI
   - No command-line batch processing

4. **Single File**: Designed for single markdown files
   - No multi-file projects or cross-references
   - Each HTML is completely independent

## Performance Considerations

### Loading Time
- Full build: ~500 KB to download
- Parse time: Minimal (libraries are minified)
- Render time: Depends on markdown complexity, typically <1 second

### Runtime Performance
- DOM manipulation minimized
- Syntax highlighting runs only once on page load
- Math rendering cached by KaTeX
- No unnecessary re-renders
- Efficient search algorithm (skips code blocks)

## Troubleshooting

### Issue: Syntax highlighting not working
- Ensure "Enable syntax highlighting" is toggled on
- Check that vendor/highlight.min.js exists
- Verify code blocks use valid language identifiers

### Issue: Math not rendering
- Ensure "Enable Math/LaTeX rendering" is toggled on
- Check that vendor/katex.min.js and vendor/katex.min.css exist
- Verify math uses $ for inline or $$ for display

### Issue: Output blocks getting syntax highlighting
- This is a known issue that was fixed
- Output blocks should be detected before syntax highlighting runs
- Ensure you're using the latest version of md_to_html.py

### Issue: Large HTML file size
- Disable syntax highlighting if not needed (-~122 KB)
- Disable math rendering if not needed (-~300 KB)
- Minimal build is ~70 KB with just markdown parsing

### Issue: Line numbers on output blocks
- This was a bug that has been fixed
- Line numbers now automatically skip blocks with class "output"
- Update to latest version of md_to_html.py

## Credits

### Vendor Libraries
- **Marked.js** (https://marked.js.org/) - Fast markdown parser
- **DOMPurify** (https://github.com/cure53/DOMPurify) - XSS sanitizer
- **Highlight.js** (https://highlightjs.org/) - Syntax highlighting
- **KaTeX** (https://katex.org/) - Fast math typesetting

### Framework
- **Streamlit** (https://streamlit.io/) - Web application framework

## License

This project is provided as-is for educational and commercial use. Vendor libraries retain their original licenses (MIT/Apache 2.0).
