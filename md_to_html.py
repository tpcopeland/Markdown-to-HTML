"""
Markdown to HTML Converter with Streamlit UI

Security enhancements applied:
- CSS injection prevention: validate base_font_size and content_width parameters
- Path traversal prevention: filename validation rejects dotfiles and enforces alphanumeric start
- Path traversal prevention: safe_read_file() ensures files are within base directory
- Path traversal prevention: validate_project_path() blocks access to sensitive system directories
- Input sanitization: all user inputs are validated before use
- HTML escaping: proper escaping for HTML, JavaScript, and CSS contexts

Bug fixes applied:
- Math rendering: protect math expressions ($...$, $$...$$) from Markdown parser
- Download button: use session state to persist button across re-renders
- Relative paths: resolve VENDOR_DIR relative to script location, not CWD
"""
import os
import re
import hashlib
import datetime
import streamlit as st
from pathlib import Path
from typing import List, Dict, Optional, Tuple
try:
    import tomli as toml  # Python < 3.11
except ImportError:
    try:
        import tomllib as toml  # Python >= 3.11
    except ImportError:
        toml = None

# ---------- App config ----------
APP_TITLE = "Markdown -> Offline HTML"
# Resolve paths relative to the script file (Fix: fragile relative paths)
APP_DIR = os.path.dirname(os.path.abspath(__file__))
VENDOR_DIR = os.path.join(APP_DIR, "vendor")
MARKED_FILE = "marked.umd.min.js"
PURIFY_FILE = "purify.min.js"
HIGHLIGHT_FILE = "highlight.min.js"
KATEX_JS_FILE = "katex.min.js"
KATEX_CSS_FILE = "katex.min.css"

# ---------- Helpers ----------
@st.cache_data
def read_text_file(path: str) -> str:
    """Read text file with error handling."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        st.error(f"Failed to read {path}: {e}")
        st.stop()

def validate_vendor_path(base_dir: str, filename: str) -> str:
    """Validate and resolve vendor file path to prevent traversal."""
    # Require filename to start with alphanumeric (not dot) to prevent access to hidden files
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', filename):
        st.error(f"Invalid filename: {filename}")
        st.stop()
    path = os.path.join(base_dir, filename)
    resolved = os.path.abspath(path)
    base_resolved = os.path.abspath(base_dir)
    if not resolved.startswith(base_resolved):
        st.error("Path traversal detected")
        st.stop()
    return resolved

def validate_js_file(content: str, name: str) -> None:
    """Basic validation that file looks like JavaScript."""
    if not content.strip():
        st.error(f"{name} is empty")
        st.stop()
    if len(content) < 100:
        st.error(f"{name} appears invalid (too short)")
        st.stop()

@st.cache_data
def load_vendor_js(use_highlight: bool = False, use_katex: bool = False) -> dict:
    """Load and validate vendor JavaScript files."""
    marked_path = validate_vendor_path(VENDOR_DIR, MARKED_FILE)
    purify_path = validate_vendor_path(VENDOR_DIR, PURIFY_FILE)
    if not os.path.exists(marked_path) or not os.path.exists(purify_path):
        st.error("Missing vendor JS. Place Marked and DOMPurify in ./vendor/ as marked.umd.min.js and purify.min.js.")
        st.stop()
    marked_js = read_text_file(marked_path)
    purify_js = read_text_file(purify_path)
    validate_js_file(marked_js, "Marked.js")
    validate_js_file(purify_js, "DOMPurify")

    result = {"marked": marked_js, "purify": purify_js}

    if use_highlight:
        highlight_path = validate_vendor_path(VENDOR_DIR, HIGHLIGHT_FILE)
        if os.path.exists(highlight_path):
            highlight_js = read_text_file(highlight_path)
            validate_js_file(highlight_js, "Highlight.js")
            result["highlight"] = highlight_js
        else:
            st.warning("highlight.min.js not found in vendor folder. Syntax highlighting disabled.")

    if use_katex:
        katex_js_path = validate_vendor_path(VENDOR_DIR, KATEX_JS_FILE)
        katex_css_path = validate_vendor_path(VENDOR_DIR, KATEX_CSS_FILE)
        if os.path.exists(katex_js_path) and os.path.exists(katex_css_path):
            katex_js = read_text_file(katex_js_path)
            katex_css = read_text_file(katex_css_path)
            validate_js_file(katex_js, "KaTeX")
            result["katex_js"] = katex_js
            result["katex_css"] = katex_css
        else:
            st.warning("KaTeX files not found in vendor folder. Math rendering disabled.")

    return result

def escape_html(s: str) -> str:
    """Escape HTML special characters including quotes."""
    if not s:
        return ""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#x27;"))

def escape_js_string(s: str) -> str:
    """Escape string for safe inclusion in a JavaScript variable."""
    if not s:
        return ""
    return (s.replace("\\", "\\\\")
             .replace("'", "\\'")
             .replace('"', '\\"')
             .replace("\n", "\\n")
             .replace("\r", "\\r")
             .replace("\t", "\\t")
             .replace("</script>", "<\\/script>"))

def escape_for_script_tag(s: str) -> str:
    """Escape string for safe inclusion in a <script> data block."""
    if not s:
        return ""
    # Only need to escape </script> to prevent HTML parser from closing the tag
    return s.replace("</script>", "<\\/script>")

def validate_date(date_str: str) -> bool:
    """Validate ISO date format."""
    if not date_str:
        return True
    try:
        datetime.date.fromisoformat(date_str)
        return True
    except ValueError:
        return False

def validate_css_size(value: str) -> bool:
    """Validate CSS size value to prevent injection."""
    if not value:
        return False
    # Allow percentage, px, em, rem, vh, vw with optional decimal
    pattern = r'^\d+(\.\d+)?(px|%|em|rem|vh|vw)$'
    return bool(re.match(pattern, value))

def sanitize_css_size(value: str, default: str) -> str:
    """Sanitize CSS size value, return default if invalid."""
    if validate_css_size(value):
        return value
    st.warning(f"Invalid CSS size value: {value}. Using default: {default}")
    return default

def sanitize_filename(name: str) -> str:
    """Sanitize filename for download."""
    if not name:
        return "document.html"
    # Remove characters not in: word chars, whitespace, dot, underscore, or hyphen
    name = re.sub(r'[^\w\s._-]', '', name)
    # Replace multiple whitespace with single underscore
    name = re.sub(r'[\s]+', '_', name)
    # Remove leading/trailing dots, underscores, or hyphens
    name = name.strip('._-')
    if not name:
        return "document.html"
    if not name.endswith('.html'):
        name += '.html'
    return name[:255]

def safe_read_file(base_dir: str, relative_path: str) -> str:
    """
    Safely read a file ensuring it is within the base directory.
    Prevents path traversal attacks (e.g., ../../../../etc/passwd).
    """
    # Normalize and resolve both paths to absolute
    base_abs = os.path.abspath(os.path.normpath(base_dir))
    # Join and normalize the target path
    target_abs = os.path.abspath(os.path.normpath(os.path.join(base_dir, relative_path)))

    # Ensure the resolved target starts with the base directory
    # Use os.sep to ensure we're checking full directory components
    if not (target_abs.startswith(base_abs + os.sep) or target_abs == base_abs):
        raise ValueError(f"Security violation: Path '{relative_path}' resolves outside base directory.")

    with open(target_abs, "r", encoding="utf-8") as f:
        return f.read()

# ---------- mdBook Integration ----------

class Chapter:
    """Represents a chapter in an mdBook."""
    def __init__(self, title: str, path: Optional[str] = None, level: int = 0,
                 is_draft: bool = False, is_separator: bool = False,
                 is_part_title: bool = False, number: Optional[str] = None):
        self.title = title
        self.path = path
        self.level = level
        self.is_draft = is_draft
        self.is_separator = is_separator
        self.is_part_title = is_part_title
        self.number = number
        self.content = ""
        self.children: List[Chapter] = []

    def __repr__(self):
        return f"Chapter(title={self.title}, path={self.path}, level={self.level})"

def parse_book_toml(toml_path: str) -> Dict:
    """Parse book.toml configuration file."""
    if toml is None:
        st.warning("TOML parser not available. Install 'tomli' for Python < 3.11 or use Python >= 3.11")
        return {"book": {"title": "Book", "authors": [], "language": "en"}}

    try:
        with open(toml_path, 'rb') as f:
            config = toml.load(f)
        return config
    except Exception as e:
        st.error(f"Failed to parse book.toml: {e}")
        return {"book": {"title": "Book", "authors": [], "language": "en"}}

def parse_summary_md(summary_path: str) -> List[Chapter]:
    """Parse SUMMARY.md file and extract chapter structure."""
    try:
        with open(summary_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        st.error(f"Failed to read SUMMARY.md: {e}")
        return []

    chapters = []
    lines = content.split('\n')
    numbered_chapter_count = [0] * 10  # Support up to 10 levels of nesting
    in_numbered_section = False

    for line in lines:
        # Skip empty lines
        if not line.strip():
            continue

        # Check for separator (---)
        if re.match(r'^-{3,}$', line.strip()):
            chapters.append(Chapter("", is_separator=True))
            continue

        # Check for part title (# Title)
        if line.strip().startswith('#'):
            title = line.strip().lstrip('#').strip()
            if title.lower() != 'summary':  # Ignore the main "Summary" title
                chapters.append(Chapter(title, is_part_title=True))
            continue

        # Check for chapter link: [Title](path) or [Title]()
        link_match = re.match(r'^(\s*)([-*])\s+\[([^\]]+)\]\(([^)]*)\)\s*$', line)
        if link_match:
            indent, marker, title, path = link_match.groups()
            level = len(indent) // 2  # Assuming 2 spaces per level
            is_draft = not path.strip()

            # Determine if this is a numbered chapter
            if not in_numbered_section and level == 0 and not is_draft:
                # First root-level chapter with content starts numbered section
                in_numbered_section = True

            # Generate chapter number if in numbered section
            chapter_number = None
            if in_numbered_section and not is_draft:
                numbered_chapter_count[level] += 1
                # Reset deeper levels
                for i in range(level + 1, len(numbered_chapter_count)):
                    numbered_chapter_count[i] = 0
                # Build number string (e.g., "1.2.3")
                number_parts = [str(numbered_chapter_count[i]) for i in range(level + 1) if numbered_chapter_count[i] > 0]
                chapter_number = '.'.join(number_parts)

            chapter = Chapter(
                title=title.strip(),
                path=path.strip() if path.strip() else None,
                level=level,
                is_draft=is_draft,
                number=chapter_number
            )
            chapters.append(chapter)

    return chapters

def read_markdown_file(base_path: str, file_path: str) -> str:
    """Read a markdown file from mdBook src directory with path traversal protection."""
    try:
        # Use safe_read_file to prevent path traversal attacks
        return safe_read_file(base_path, file_path)
    except ValueError as e:
        # Security violation - path traversal attempted
        st.error(f"Security Error: {e}")
        return f"<!-- Security Error: Attempted path traversal to {file_path} -->\n"
    except Exception as e:
        st.warning(f"Failed to read {file_path}: {e}")
        return f"<!-- Error reading {file_path}: {e} -->\n"

def combine_chapters(chapters: List[Chapter], base_path: str) -> Tuple[str, List[Dict]]:
    """
    Combine all chapters into a single markdown document.
    Returns the combined markdown and a list of chapter metadata.
    """
    combined_md = ""
    chapter_metadata = []

    for i, chapter in enumerate(chapters):
        if chapter.is_separator:
            combined_md += "\n---\n\n"
            continue

        if chapter.is_part_title:
            combined_md += f"\n# {chapter.title}\n\n"
            continue

        if chapter.is_draft:
            combined_md += f"\n## {chapter.title} (Draft)\n\n"
            combined_md += "*This chapter is under construction.*\n\n"
            continue

        if chapter.path:
            # Add chapter heading
            heading_level = "#" * (chapter.level + 2)  # H2 for root level, H3 for level 1, etc.
            chapter_title = chapter.title
            if chapter.number:
                chapter_title = f"{chapter.number}. {chapter.title}"

            combined_md += f"\n{heading_level} {chapter_title}\n\n"

            # Read and add chapter content
            content = read_markdown_file(base_path, chapter.path)

            # Remove the first H1 from content if it exists (we already added the heading)
            content_lines = content.split('\n')
            if content_lines and content_lines[0].strip().startswith('# '):
                content_lines = content_lines[1:]
            content = '\n'.join(content_lines)

            combined_md += content + "\n\n"

            # Track chapter metadata for navigation
            chapter_metadata.append({
                "title": chapter_title,
                "number": chapter.number,
                "level": chapter.level,
                "index": i
            })

    return combined_md, chapter_metadata

def validate_project_path(project_path: str) -> Tuple[bool, str]:
    """
    Validate an mdBook project path for security.
    Returns: (is_valid, error_message)
    """
    if not project_path:
        return False, "Project path is empty."

    # Normalize the path
    normalized = os.path.normpath(project_path)

    # Check for path traversal patterns
    if '..' in normalized.split(os.sep):
        return False, "Path traversal patterns (..) are not allowed."

    # Check if it's an absolute path pointing to sensitive system directories
    abs_path = os.path.abspath(normalized)
    sensitive_dirs = ['/etc', '/var', '/root', '/home/root', '/sys', '/proc', '/dev', '/boot']
    for sensitive in sensitive_dirs:
        if abs_path == sensitive or abs_path.startswith(sensitive + os.sep):
            return False, f"Access to system directory '{sensitive}' is not allowed."

    return True, ""

def process_mdbook_project(project_path: str) -> Tuple[str, Dict, List[Dict]]:
    """
    Process an mdBook project directory.
    Returns: (combined_markdown, book_config, chapter_metadata)
    """
    # Validate the project path for security
    is_valid, error_msg = validate_project_path(project_path)
    if not is_valid:
        st.error(f"Security Error: {error_msg}")
        return "", {"book": {"title": "Book", "authors": [], "language": "en"}}, []

    project_path = Path(os.path.abspath(project_path))

    # Read book.toml
    book_toml_path = project_path / "book.toml"
    if book_toml_path.exists():
        config = parse_book_toml(str(book_toml_path))
    else:
        st.warning("book.toml not found, using defaults")
        config = {"book": {"title": "Book", "authors": [], "language": "en"}}

    # Read SUMMARY.md
    summary_path = project_path / "src" / "SUMMARY.md"
    if not summary_path.exists():
        st.error("SUMMARY.md not found in src/ directory")
        return "", config, []

    chapters = parse_summary_md(str(summary_path))

    # Combine all chapters - base_path is the src directory
    base_path = str(project_path / "src")
    combined_md, chapter_metadata = combine_chapters(chapters, base_path)

    return combined_md, config, chapter_metadata

# ---------- HTML Generation ----------
def get_theme_css(theme_preset: str) -> list:
    """Get CSS variables for different theme presets."""
    themes = {
        "default": [
            ":root{--bg:#ffffff;--fg:#111111;--muted:#555555;--link:#0b63ce;--linkv:#6a32c9;--border:#dddddd;--code:#f6f8fa;--accent:#eef1f5}",
            "html[data-theme=\"dark\"]{--bg:#0f1115;--fg:#e6e6e6;--muted:#a0a0a0;--link:#6aa7ff;--linkv:#c39bff;--border:#2a2e37;--code:#1a1d24;--accent:#20232b}",
        ],
        "github": [
            ":root{--bg:#ffffff;--fg:#24292f;--muted:#57606a;--link:#0969da;--linkv:#8250df;--border:#d0d7de;--code:#f6f8fa;--accent:#f6f8fa}",
            "html[data-theme=\"dark\"]{--bg:#0d1117;--fg:#c9d1d9;--muted:#8b949e;--link:#58a6ff;--linkv:#bc8cff;--border:#30363d;--code:#161b22;--accent:#161b22}",
        ],
        "academic": [
            ":root{--bg:#fffff8;--fg:#1a1a1a;--muted:#666666;--link:#2563eb;--linkv:#7c3aed;--border:#d4d4d4;--code:#f5f5f5;--accent:#fafafa;font-family:Georgia,Cambria,'Times New Roman',Times,serif}",
            "html[data-theme=\"dark\"]{--bg:#1a1a1a;--fg:#e5e5e5;--muted:#a3a3a3;--link:#60a5fa;--linkv:#a78bfa;--border:#404040;--code:#262626;--accent:#262626}",
            "body{line-height:1.7}",
            "main{padding:2rem}",
        ],
        "minimal": [
            ":root{--bg:#ffffff;--fg:#000000;--muted:#666666;--link:#000000;--linkv:#333333;--border:#e0e0e0;--code:#f8f8f8;--accent:#fafafa}",
            "html[data-theme=\"dark\"]{--bg:#000000;--fg:#ffffff;--muted:#999999;--link:#ffffff;--linkv:#cccccc;--border:#333333;--code:#111111;--accent:#0a0a0a}",
            "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.6}",
            "a{text-decoration:none;border-bottom:1px solid var(--link)}",
        ],
        "dark": [
            ":root,html{--bg:#1e1e1e;--fg:#d4d4d4;--muted:#858585;--link:#4fc3f7;--linkv:#ba68c8;--border:#3e3e3e;--code:#2d2d2d;--accent:#252526}",
            "html[data-theme=\"dark\"]{--bg:#1e1e1e;--fg:#d4d4d4;--muted:#858585;--link:#4fc3f7;--linkv:#ba68c8;--border:#3e3e3e;--code:#2d2d2d;--accent:#252526}",
            "html{color-scheme:dark}",
        ],
    }
    return themes.get(theme_preset, themes["default"])

def get_highlight_theme_css(highlight_theme: str) -> str:
    """Get CSS for syntax highlighting themes."""
    themes = {
        "github-light": """
.hljs{background:#f6f8fa;color:#24292e}.hljs-doctag,.hljs-keyword,.hljs-meta .hljs-keyword,.hljs-template-tag,.hljs-template-variable,.hljs-type,.hljs-variable.language_{color:#d73a49}.hljs-title,.hljs-title.class_,.hljs-title.class_.inherited__,.hljs-title.function_{color:#6f42c1}.hljs-attr,.hljs-attribute,.hljs-literal,.hljs-meta,.hljs-number,.hljs-operator,.hljs-selector-attr,.hljs-selector-class,.hljs-selector-id,.hljs-variable{color:#005cc5}.hljs-meta .hljs-string,.hljs-regexp,.hljs-string{color:#032f62}.hljs-built_in,.hljs-symbol{color:#e36209}.hljs-code,.hljs-comment,.hljs-formula{color:#6a737d}.hljs-name,.hljs-quote,.hljs-selector-pseudo,.hljs-selector-tag{color:#22863a}.hljs-subst{color:#24292e}.hljs-section{color:#005cc5;font-weight:700}.hljs-bullet{color:#735c0f}.hljs-emphasis{color:#24292e;font-style:italic}.hljs-strong{color:#24292e;font-weight:700}.hljs-addition{color:#22863a;background-color:#f0fff4}.hljs-deletion{color:#b31d28;background-color:#ffeef0}
""",
        "github-dark": """
.hljs{background:#0d1117;color:#c9d1d9}.hljs-doctag,.hljs-keyword,.hljs-meta .hljs-keyword,.hljs-template-tag,.hljs-template-variable,.hljs-type,.hljs-variable.language_{color:#ff7b72}.hljs-title,.hljs-title.class_,.hljs-title.class_.inherited__,.hljs-title.function_{color:#d2a8ff}.hljs-attr,.hljs-attribute,.hljs-literal,.hljs-meta,.hljs-number,.hljs-operator,.hljs-selector-attr,.hljs-selector-class,.hljs-selector-id,.hljs-variable{color:#79c0ff}.hljs-meta .hljs-string,.hljs-regexp,.hljs-string{color:#a5d6ff}.hljs-built_in,.hljs-symbol{color:#ffa657}.hljs-code,.hljs-comment,.hljs-formula{color:#8b949e}.hljs-name,.hljs-quote,.hljs-selector-pseudo,.hljs-selector-tag{color:#7ee787}.hljs-subst{color:#c9d1d9}.hljs-section{color:#1f6feb;font-weight:700}.hljs-bullet{color:#f2cc60}.hljs-emphasis{color:#c9d1d9;font-style:italic}.hljs-strong{color:#c9d1d9;font-weight:700}.hljs-addition{color:#aff5b4;background-color:#033a16}.hljs-deletion{color:#ffdcd7;background-color:#67060c}
""",
        "monokai": """
.hljs{background:#272822;color:#ddd}.hljs-tag,.hljs-keyword,.hljs-selector-tag,.hljs-literal,.hljs-strong,.hljs-name{color:#f92672}.hljs-code{color:#66d9ef}.hljs-class .hljs-title{color:#fff}.hljs-attribute,.hljs-symbol,.hljs-regexp,.hljs-link{color:#bf79db}.hljs-string,.hljs-bullet,.hljs-subst,.hljs-title,.hljs-section,.hljs-emphasis,.hljs-type,.hljs-built_in,.hljs-selector-attr,.hljs-selector-pseudo,.hljs-addition,.hljs-variable,.hljs-template-tag,.hljs-template-variable{color:#a6e22e}.hljs-comment,.hljs-quote,.hljs-deletion,.hljs-meta{color:#75715e}.hljs-keyword,.hljs-selector-tag,.hljs-literal,.hljs-doctag,.hljs-title,.hljs-section,.hljs-type,.hljs-name{font-weight:700}
""",
        "atom-one-dark": """
.hljs{background:#282c34;color:#abb2bf}.hljs-comment,.hljs-quote{color:#5c6370;font-style:italic}.hljs-doctag,.hljs-keyword,.hljs-formula{color:#c678dd}.hljs-section,.hljs-name,.hljs-selector-tag,.hljs-deletion,.hljs-subst{color:#e06c75}.hljs-literal{color:#56b6c2}.hljs-string,.hljs-regexp,.hljs-addition,.hljs-attribute,.hljs-meta .hljs-string{color:#98c379}.hljs-attr,.hljs-variable,.hljs-template-variable,.hljs-type,.hljs-selector-class,.hljs-selector-attr,.hljs-selector-pseudo,.hljs-number{color:#d19a66}.hljs-symbol,.hljs-bullet,.hljs-link,.hljs-meta,.hljs-selector-id,.hljs-title{color:#61aeee}.hljs-built_in,.hljs-title.class_,.hljs-class .hljs-title{color:#e6c07b}.hljs-emphasis{font-style:italic}.hljs-strong{font-weight:700}.hljs-link{text-decoration:underline}
""",
    }
    return themes.get(highlight_theme, themes["github-light"])

def generate_css(toc_mode: str, back_to_top: bool, search_enabled: bool, collapsible_mode: str, theme_preset: str = "default", highlight_enabled: bool = False, highlight_theme: str = "github-light", line_numbers: bool = False, base_font_size: str = "100%", content_width: str = "900px") -> str:
    """Generate CSS based on enabled features."""
    # Validate and sanitize CSS values to prevent injection
    safe_font_size = sanitize_css_size(base_font_size, "100%")
    safe_content_width = sanitize_css_size(content_width, "900px")

    base_css = get_theme_css(theme_preset) + [
        f":root{{--base-font-size:{safe_font_size};--content-width:{safe_content_width}}}",
        "*{box-sizing:border-box}",
        f"body{{margin:0;background:var(--bg);color:var(--fg);line-height:1.55;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;font-size:var(--base-font-size)}}",
        "a{color:var(--link);text-decoration:underline}a:visited{color:var(--linkv)}a:hover{opacity:.8}",
        "header.toolbar{position:sticky;top:0;z-index:10;background:var(--bg);border-bottom:1px solid var(--border)}",
        "header .wrap{max-width:1080px;margin:0 auto;padding:.5rem 1rem;display:flex;gap:.75rem;align-items:center;justify-content:space-between;flex-wrap:wrap}",
        "main{max-width:var(--content-width);margin:0 auto;padding:1rem}",
        "nav#toc{border:1px solid var(--border);background:var(--accent);padding:1rem;border-radius:.5rem;margin:1rem 0 2rem 0}",
        "h1,h2,h3,h4,h5,h6{position:relative;line-height:1.25;margin:1.5rem 0 .75rem 0;scroll-margin-top:80px}",
        "h1{font-size:2rem}h2{font-size:1.5rem}h3{font-size:1.25rem}",
        ".heading-anchor{position:absolute;left:-1.5rem;opacity:0;color:var(--muted);text-decoration:none;font-weight:normal;padding:.25rem}",
        "h1:hover .heading-anchor,h2:hover .heading-anchor,h3:hover .heading-anchor,h4:hover .heading-anchor,h5:hover .heading-anchor,h6:hover .heading-anchor,.heading-anchor:focus{opacity:1}",
        "p{margin:.75rem 0}",
        "pre{position:relative;background:var(--code);padding:1rem;overflow:auto;border-radius:.4rem;border:1px solid var(--border);margin:1rem 0}",
        "pre.output{background:var(--bg);border-left:4px solid var(--muted);border-radius:0 .4rem .4rem 0}",
        "pre.output code{color:var(--muted)}",
        "code{background:var(--code);padding:.15rem .3rem;border-radius:.3rem;border:1px solid var(--border);font-family:ui-monospace,SFMono-Regular,Consolas,monospace}",
        "pre code{background:transparent;padding:0;border:none}",
        ".code-wrapper{position:relative}",
        ".copy-btn{position:absolute;top:.5rem;right:.5rem;background:var(--accent);border:1px solid var(--border);color:var(--fg);padding:.25rem .5rem;border-radius:.3rem;cursor:pointer;font-size:.8rem;opacity:.7;transition:opacity .2s;z-index:5}",
        ".copy-btn:hover{opacity:1}",
        ".copy-btn.copied{background:var(--link);color:#fff;border-color:var(--link)}",
        ".table-wrapper{overflow-x:auto;margin:1rem 0;position:relative;box-shadow:inset -10px 0 10px -10px rgba(0,0,0,.1),inset 10px 0 10px -10px rgba(0,0,0,.1)}",
        ".table-wrapper table{margin:0}",
        "table{border-collapse:collapse;margin:1rem 0;width:100%}",
        "th,td{border:1px solid var(--border);padding:.5rem;vertical-align:top;text-align:left}",
        "th{background:var(--accent);font-weight:600}",
        "blockquote{border-left:4px solid var(--border);margin:1rem 0;padding:.5rem 1rem;color:var(--muted);background:var(--accent)}",
        "img{max-width:100%;height:auto}",
        "ul,ol{margin:.75rem 0;padding-left:2rem}",
        "li{margin:.25rem 0}",
        "hr{border:none;border-top:1px solid var(--border);margin:2rem 0}",
        "hr.labeled{position:relative;text-align:center;margin:3rem 0;border-top:2px solid var(--border)}",
        "hr.labeled::after{content:attr(data-label);position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--bg);padding:0 1rem;color:var(--muted);font-size:.9em;font-weight:600;white-space:nowrap}",
        "a.skip{position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden}",
        "a.skip:focus{position:static;width:auto;height:auto;margin:.5rem;display:inline-block;background:var(--accent);padding:.4rem .6rem;border-radius:.3rem}",
        "@media print{html{color-scheme:light}body{font-size:11pt}header.toolbar,button#themeToggle,#tocSidebarToggle,#toc-sidebar,#toc-backdrop,.search-wrap,.copy-btn,.back-to-top,.heading-anchor{display:none!important}pre,table,blockquote,img{page-break-inside:avoid}h1,h2,h3,h4,h5,h6{page-break-after:avoid}a[href^=\"http\"]::after{content:\" (\" attr(href) \")\";font-size:.85em;color:var(--muted);word-break:break-all}main{max-width:100%;padding:.5cm}pre{border:1px solid #ccc;overflow:visible;white-space:pre-wrap}.collapsible::after{display:none}.section-body{display:block!important}}"
    ]
    
    if back_to_top:
        base_css.append(".back-to-top{margin:1rem 0 2rem 0}.back-to-top a{display:inline-block;border:1px solid var(--border);background:var(--accent);color:var(--fg);padding:.25rem .5rem;border-radius:.3rem;text-decoration:none}.back-to-top a:hover{opacity:.8}")
    
    if collapsible_mode != "none":
        base_css.append(".collapsible{cursor:pointer;user-select:none}.collapsible::after{content:\" [-]\";font-weight:normal;color:var(--muted)}.collapsed + .section-body{display:none}.collapsed.collapsible::after{content:\" [+]\"}.section-body{margin-top:.5rem}")
    
    if search_enabled:
        base_css.append(".search-wrap{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}#searchBox{min-width:220px;padding:.3rem .5rem;border:1px solid var(--border);border-radius:.3rem;background:var(--bg);color:var(--fg)}#searchBox:focus{outline:2px solid var(--link)}#searchClear{border:1px solid var(--border);background:var(--accent);color:var(--fg);padding:.25rem .5rem;border-radius:.3rem;cursor:pointer}#searchClear:hover{opacity:.8}mark.hl{background:#ffe58f;padding:0 .1rem;border-radius:.1rem}")
    
    if toc_mode == "sidebar":
        base_css.append("#tocSidebarToggle{border:1px solid var(--border);background:var(--accent);color:var(--fg);padding:.4rem .7rem;border-radius:.4rem;cursor:pointer;margin-left:.5rem}#tocSidebarToggle:hover{opacity:.8}#toc-sidebar{position:fixed;left:0;top:0;height:100vh;width:320px;max-width:85vw;background:var(--bg);color:var(--fg);border-right:1px solid var(--border);transform:translateX(-100%);transition:transform .2s ease;z-index:1000;box-shadow:2px 0 8px rgba(0,0,0,.15)}#toc-sidebar.open{transform:translateX(0)}#toc-sidebar .toc-header{display:flex;align-items:center;justify-content:space-between;padding:.75rem 1rem;border-bottom:1px solid var(--border)}#toc-sidebar ol{margin:0;padding:1rem 1.25rem 2rem 1.75rem;overflow:auto;height:calc(100vh - 60px)}#toc-sidebar ol a{display:block;padding:.25rem 0}#tocSidebarClose{border:1px solid var(--border);background:var(--accent);color:var(--fg);padding:.2rem .5rem;border-radius:.3rem;cursor:pointer}#tocSidebarClose:hover{opacity:.8}#toc-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.25);z-index:900}#toc-backdrop.hidden{display:none}")

    if line_numbers:
        base_css.append("pre.line-numbers{padding-left:3.5rem}pre.line-numbers code{display:block;position:relative}pre.line-numbers .line-numbers-rows{position:absolute;pointer-events:none;top:1rem;left:0;width:3rem;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:1em;line-height:1.5;letter-spacing:normal;border-right:1px solid var(--border);user-select:none;counter-reset:linenumber}pre.line-numbers .line-numbers-rows>span{display:block;counter-increment:linenumber;text-align:right;padding-right:.5rem;color:var(--muted)}pre.line-numbers .line-numbers-rows>span:before{content:counter(linenumber)}pre code{line-height:1.5}@media print{pre.line-numbers .line-numbers-rows{border-right-color:#999}}")

    if highlight_enabled:
        base_css.append(get_highlight_theme_css(highlight_theme))

    return "".join(base_css)

def generate_toolbar(title: str, toc_mode: str, search_enabled: bool, theme_preset: str = "Default") -> str:
    """Generate toolbar HTML."""
    sidebar_toggle = (
        '<button id="tocSidebarToggle" type="button" aria-pressed="false" aria-label="Toggle table of contents sidebar">ToC</button>'
        if toc_mode == "sidebar" else ""
    )
    search_ui = (
        '<div id="searchWrap" class="search-wrap" role="search">'
        '  <input id="searchBox" type="search" placeholder="Search..." aria-label="Search document">'
        '  <span id="searchCount" aria-live="polite" aria-atomic="true"></span>'
        '  <button id="searchClear" type="button" aria-label="Clear search">Clear</button>'
        '</div>'
        if search_enabled else ""
    )
    # Only show theme toggle if not using Dark theme preset
    theme_toggle = (
        '<button id="themeToggle" type="button" aria-pressed="false" aria-label="Toggle light and dark theme">Toggle Light/Dark</button>\n      '
        if theme_preset != "Dark" else ""
    )
    return (
        '<header class="toolbar" role="banner" aria-label="Toolbar">\n'
        '  <div class="wrap">\n'
        f'    <div>{escape_html(title)}</div>\n'
        '    <div>\n'
        f'      {theme_toggle}'
        f'{sidebar_toggle}\n'
        f'      {search_ui}\n'
        '    </div>\n'
        '  </div>\n'
        '</header>'
    )



def generate_toc_containers(toc_mode: str) -> tuple[str, str]:
    """Generate ToC container HTML."""
    top_toc = (
        '  <nav id="toc" aria-label="Table of contents">\n'
        '    <strong>Table of Contents</strong>\n'
        '    <ul id="toc-list"></ul>\n'
        '  </nav>\n'
        if toc_mode == "top" else ""
    )
    sidebar_toc = (
        '<aside id="toc-sidebar" class="closed" aria-label="Table of contents" aria-hidden="true">'
        '  <div class="toc-header">'
        '    <strong>Table of Contents</strong>'
        '    <button id="tocSidebarClose" type="button" aria-label="Close sidebar">x</button>'
        '  </div>'
        '  <ul id="toc-list-sidebar"></ul>'
        '</aside>'
        '<div id="toc-backdrop" class="hidden" aria-hidden="true"></div>'
        if toc_mode == "sidebar" else ""
    )
    return top_toc, sidebar_toc

def generate_javascript(
    vendor_libs: dict,
    toc_mode: str,
    toc_levels: str,
    collapsible_mode: str,
    start_collapsed: bool,
    back_to_top: bool,
    search_enabled: bool,
    highlight_enabled: bool = False,
    katex_enabled: bool = False,
    line_numbers: bool = False
) -> str:
    """Generate JavaScript code with constants."""
    marked_js = vendor_libs.get("marked", "")
    purify_js = vendor_libs.get("purify", "")
    highlight_js = vendor_libs.get("highlight", "")
    katex_js = vendor_libs.get("katex_js", "")

    toc_mode_js = {"top": "'top'", "sidebar": "'sidebar'", "none": "'none'"}.get(toc_mode, "'none'")
    toc_levels_js = {"h2": "'h2'", "h2h3": "'h2h3'", "h2h3h4": "'h2h3h4'"}.get(toc_levels, "'h2'")
    collapse_mode_js = {"none": "'none'", "h2": "'h2'", "h2h3": "'h2h3'"}.get(collapsible_mode, "'none'")
    
    js_constants = f"""
  var TOC_MODE = {toc_mode_js};
  var TOC_LEVELS = {toc_levels_js};
  var COLLAPSE_MODE = {collapse_mode_js};
  var START_COLLAPSED = {'true' if start_collapsed else 'false'};
  var BACK_TO_TOP = {'true' if back_to_top else 'false'};
  var SEARCH_ENABLED = {'true' if search_enabled else 'false'};
  var CSS_CLASS_OPEN = 'open';
  var CSS_CLASS_CLOSED = 'closed';
  var CSS_CLASS_HIDDEN = 'hidden';
  var CSS_CLASS_COLLAPSIBLE = 'collapsible';
  var CSS_CLASS_COLLAPSED = 'collapsed';
  var CSS_CLASS_SECTION_BODY = 'section-body';
"""
    
    # Main JS with improved search, ID deduplication, and fixes
    main_js = """
  // Theme toggle (only if button exists)
  var html = document.documentElement;
  var btn = document.getElementById('themeToggle');
  if (btn) {
    function setTheme(t){
      html.setAttribute('data-theme', t);
      btn.setAttribute('aria-pressed', t === 'dark' ? 'true' : 'false');
      try{ localStorage.setItem('theme', t); }catch(e){}
    }
    var saved = null; try{ saved = localStorage.getItem('theme'); }catch(e){}
    setTheme(saved || 'light');
    btn.addEventListener('click', function(){
      setTheme(html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    });
  }

  // Sidebar ToC toggle
  if (TOC_MODE === 'sidebar'){
    var sb = document.getElementById('toc-sidebar');
    var bd = document.getElementById('toc-backdrop');
    var openBtn = document.getElementById('tocSidebarToggle');
    var closeBtn = document.getElementById('tocSidebarClose');
    function open(){
      sb.classList.add(CSS_CLASS_OPEN);
      sb.classList.remove(CSS_CLASS_CLOSED);
      sb.setAttribute('aria-hidden','false');
      openBtn.setAttribute('aria-pressed','true');
      bd.classList.remove(CSS_CLASS_HIDDEN);
    }
    function close(){
      sb.classList.remove(CSS_CLASS_OPEN);
      sb.classList.add(CSS_CLASS_CLOSED);
      sb.setAttribute('aria-hidden','true');
      openBtn.setAttribute('aria-pressed','false');
      bd.classList.add(CSS_CLASS_HIDDEN);
    }
    if (openBtn) openBtn.addEventListener('click', open);
    if (closeBtn) closeBtn.addEventListener('click', close);
    if (bd) bd.addEventListener('click', close);
    document.addEventListener('keydown', function(e){
      if (e.key === 'Escape' && sb.classList.contains(CSS_CLASS_OPEN)) close();
    });
  }

  // Require libs
  if (!window.marked || typeof window.marked.parse !== 'function') {
    document.getElementById('md-target').textContent = 'Error: Marked.js not found.'; return;
  }
  if (!window.DOMPurify) {
    document.getElementById('md-target').textContent = 'Error: DOMPurify not found.'; return;
  }

  // Math protection: Protect math expressions from Markdown parser
  // This prevents $x * y$ from being converted to $x <em> y$
  var mathPlaceholders = [];
  function protectMath(text) {
    // Protect display math ($$...$$) first
    text = text.replace(/\$\$([^$]+)\$\$/g, function(match) {
      var idx = mathPlaceholders.length;
      mathPlaceholders.push(match);
      return '@@MATH_DISPLAY_' + idx + '@@';
    });
    // Protect inline math ($...$) - but not currency like $100
    // Use negative lookbehind simulation: match $ not preceded by backslash
    text = text.replace(/(?<![\\$])\$([^$\n]+)\$(?!\$)/g, function(match) {
      var idx = mathPlaceholders.length;
      mathPlaceholders.push(match);
      return '@@MATH_INLINE_' + idx + '@@';
    });
    return text;
  }
  function restoreMath(text) {
    return text.replace(/@@MATH_(DISPLAY|INLINE)_(\d+)@@/g, function(match, type, idx) {
      return mathPlaceholders[parseInt(idx, 10)] || match;
    });
  }

  // Render Markdown with math protection
  if (window.marked.setOptions) {
    window.marked.setOptions({ gfm:true, breaks:false, headerIds:false, mangle:false });
  }
  var md = document.getElementById('md-source').textContent;
  // Protect math expressions before Markdown parsing
  var mdProtected = protectMath(md);
  var rawHtml = window.marked.parse(mdProtected);
  // Restore math expressions after parsing
  rawHtml = restoreMath(rawHtml);
  var cleanHtml = window.DOMPurify.sanitize(rawHtml, { USE_PROFILES:{ html:true } });
  var target = document.getElementById('md-target');
  target.innerHTML = cleanHtml;

  // Utilities
  function slugify(s){
    return (s||'').toLowerCase().replace(/[^a-z0-9\s-]/g,'').trim().replace(/\s+/g,'-').replace(/-+/g,'-');
  }
  function isHeading(el){ return el && /^H[1-6]$/.test(el.tagName); }
  function headingLevel(tag){ return parseInt(tag.replace('H',''), 10); }
  function deduplicateId(id, usedIds){
    var base = id;
    var counter = 1;
    while (usedIds.has(id)) {
      id = base + '-' + counter;
      counter++;
    }
    usedIds.add(id);
    return id;
  }

  // Move explicit anchors to following heading
  Array.from(target.querySelectorAll('a[id]')).forEach(function(a){
    var next = a.nextElementSibling;
    while (next && !isHeading(next)) next = next.nextElementSibling;
    if (next && !next.id) { next.id = a.id; a.remove(); }
  });

  // Ensure IDs on all headings with deduplication
  var usedIds = new Set();
  var allHeads = Array.from(target.querySelectorAll('h1, h2, h3, h4, h5, h6'));
  allHeads.forEach(function(h){
    if (!h.id) {
      var baseId = slugify(h.textContent || 'section');
      h.id = deduplicateId(baseId, usedIds);
    } else {
      usedIds.add(h.id);
    }
  });

  // Remove any Markdown-provided ToC section from content
  var headsToRemove = [];
  allHeads.forEach(function(h){
    if ((h.textContent||'').trim().toLowerCase() === 'table of contents'){
      var nxt = h.nextElementSibling;
      if (nxt && (nxt.tagName === 'UL' || nxt.tagName === 'OL')) nxt.remove();
      headsToRemove.push(h);
    }
  });
  headsToRemove.forEach(function(h){ h.remove(); });
  
  // Rebuild allHeads after removal
  allHeads = Array.from(target.querySelectorAll('h1, h2, h3, h4, h5, h6'));

  // Build ToC (top or sidebar)
  if (TOC_MODE !== 'none'){
    var listEl = (TOC_MODE === 'sidebar') ? document.getElementById('toc-list-sidebar') : document.getElementById('toc-list');
    if (listEl){
      var headingSelectors = 'h2';
      if (TOC_LEVELS === 'h2h3') headingSelectors = 'h2, h3';
      if (TOC_LEVELS === 'h2h3h4') headingSelectors = 'h2, h3, h4';
      var tocHeads = Array.from(target.querySelectorAll(headingSelectors));
      tocHeads.forEach(function(h){
        if ((h.textContent||'').trim().toLowerCase() === 'table of contents') return;
        var li = document.createElement('li');
        var a = document.createElement('a');
        a.href = '#' + h.id; a.textContent = h.textContent;
        li.appendChild(a); listEl.appendChild(li);
      });
    }
  }

  // Wrap sections for H2..H6 (for collapsible & back-to-top)
  function wrapSections(levels){
    var heads = Array.from(target.querySelectorAll(levels.join(', ')));
    heads.forEach(function(h){
      var lvl = headingLevel(h.tagName);
      if (h.nextElementSibling && h.nextElementSibling.classList && h.nextElementSibling.classList.contains(CSS_CLASS_SECTION_BODY)) return;
      var body = document.createElement('div');
      body.className = CSS_CLASS_SECTION_BODY;
      var n = h.nextSibling;
      while (n){
        var next = n.nextSibling;
        if (n.nodeType === 1 && isHeading(n) && headingLevel(n.tagName) <= lvl) break;
        body.appendChild(n);
        n = next;
      }
      h.parentNode.insertBefore(body, h.nextSibling);
    });
  }
  wrapSections(['h2','h3','h4','h5','h6']);

  // Helper to check if body has meaningful content (not just HR or whitespace)
  function hasContent(body){
    if (!body.textContent.trim()) return false;
    var children = Array.from(body.childNodes);
    for (var i = 0; i < children.length; i++){
      var c = children[i];
      if (c.nodeType === 3 && c.textContent.trim()) return true;
      if (c.nodeType === 1 && c.tagName !== 'HR') return true;
    }
    return false;
  }

  // Collapsible sections
  if (COLLAPSE_MODE !== 'none'){
    var allowH3 = (COLLAPSE_MODE === 'h2h3');
    var heads = Array.from(target.querySelectorAll(allowH3 ? 'h2, h3' : 'h2'));
    heads.forEach(function(h){
      var body = h.nextElementSibling;
      if (!body || !body.classList.contains(CSS_CLASS_SECTION_BODY)) return;
      if (!hasContent(body)) return;
      h.classList.add(CSS_CLASS_COLLAPSIBLE);
      if (START_COLLAPSED) h.classList.add(CSS_CLASS_COLLAPSED);
      if (START_COLLAPSED) body.style.display = 'none';
      h.setAttribute('tabindex','0');
      h.setAttribute('role','button');
      h.setAttribute('aria-expanded', START_COLLAPSED ? 'false' : 'true');
    });
    target.addEventListener('click', function(e){
      var h = e.target.closest('.' + CSS_CLASS_COLLAPSIBLE); if (!h) return;
      var body = h.nextElementSibling; if (!body || !body.classList.contains(CSS_CLASS_SECTION_BODY)) return;
      var isCollapsed = h.classList.toggle(CSS_CLASS_COLLAPSED);
      body.style.display = isCollapsed ? 'none' : '';
      h.setAttribute('aria-expanded', isCollapsed ? 'false' : 'true');
    });
    target.addEventListener('keydown', function(e){
      if ((e.key === 'Enter' || e.key === ' ') && e.target.classList && e.target.classList.contains(CSS_CLASS_COLLAPSIBLE)){
        e.preventDefault(); e.target.click();
      }
    });
  }

  // Back to top links (added to H2 sections only to avoid doubling)
  if (BACK_TO_TOP){
    var topLevelHeads = Array.from(target.querySelectorAll('h2'));
    topLevelHeads.forEach(function(h){
      var body = h.nextElementSibling;
      if (body && body.classList.contains(CSS_CLASS_SECTION_BODY) && hasContent(body)){
        // Check if last child is already a back-to-top link (prevents doubling)
        var lastChild = body.lastElementChild;
        if (lastChild && lastChild.classList && lastChild.classList.contains('back-to-top')) return;

        var div = document.createElement('div');
        div.className = 'back-to-top';
        var a = document.createElement('a');
        a.href = '#top'; a.textContent = 'Back to top';
        div.appendChild(a);
        body.appendChild(div);
      }
    });
  }

  // In-page search with improved highlight (handles multiple matches)
  if (SEARCH_ENABLED){
    var input = document.getElementById('searchBox');
    var clearBtn = document.getElementById('searchClear');
    var countEl = document.getElementById('searchCount');
    var contentRoot = target;

    function clearHighlights(root){
      Array.from(root.querySelectorAll('mark.hl')).forEach(function(m){
        var parent = m.parentNode;
        while (m.firstChild) parent.insertBefore(m.firstChild, m);
        parent.removeChild(m);
      });
      contentRoot.normalize();
    }

    function highlight(q){
      clearHighlights(contentRoot);
      if (!q || q.length < 2){ countEl.textContent = ''; return; }
      var total = 0;
      var skipTags = new Set(['SCRIPT','STYLE','CODE','PRE']);
      var qLower = q.toLowerCase();

      function walk(node){
        if (node.nodeType === 1){
          if (skipTags.has(node.tagName)) return;
          var children = Array.from(node.childNodes);
          children.forEach(function(child){ walk(child); });
        } else if (node.nodeType === 3){
          var text = node.nodeValue;
          if (!text) return;
          var textLower = text.toLowerCase();
          var fragments = [];
          var lastIdx = 0;
          var idx = textLower.indexOf(qLower, lastIdx);

          while (idx !== -1){
            if (idx > lastIdx){
              fragments.push(document.createTextNode(text.slice(lastIdx, idx)));
            }
            var mark = document.createElement('mark');
            mark.className = 'hl';
            mark.appendChild(document.createTextNode(text.slice(idx, idx + q.length)));
            fragments.push(mark);
            total++;
            lastIdx = idx + q.length;
            idx = textLower.indexOf(qLower, lastIdx);
          }

          if (lastIdx < text.length){
            fragments.push(document.createTextNode(text.slice(lastIdx)));
          }

          if (fragments.length > 0){
            var parent = node.parentNode;
            fragments.forEach(function(frag){ parent.insertBefore(frag, node); });
            parent.removeChild(node);
          }
        }
      }
      walk(contentRoot);
      countEl.textContent = total ? (total + ' match' + (total===1?'':'es')) : 'No matches';
    }
    if (input){ input.addEventListener('input', function(){ highlight(input.value.trim()); }); }
    if (clearBtn){
      clearBtn.addEventListener('click', function(){
        if (input){ input.value=''; }
        clearHighlights(contentRoot);
        countEl.textContent='';
      });
    }
  }

  // Style output code blocks differently
  Array.from(target.querySelectorAll('pre code')).forEach(function(codeEl){
    var classes = codeEl.className;
    if (classes && (classes.includes('language-output') || classes.includes('output'))){
      var pre = codeEl.parentElement;
      if (pre && pre.tagName === 'PRE'){
        pre.classList.add('output');
        // Remove language class to prevent syntax highlighting
        codeEl.className = codeEl.className.replace(/language-output|output/g, '').trim();
      }
    }
  });

  // Parse and enhance horizontal rules with labels
  // Look for HTML comments immediately before HR: <!-- Section: Label -->
  Array.from(target.querySelectorAll('hr')).forEach(function(hr){
    var prev = hr.previousSibling;
    // Skip text nodes that are just whitespace
    while (prev && prev.nodeType === 3 && !prev.textContent.trim()){
      prev = prev.previousSibling;
    }
    // Check if previous node is a comment
    if (prev && prev.nodeType === 8){ // Comment node
      var comment = prev.textContent.trim();
      // Match patterns like "Section: Label" or just "Label"
      var labelMatch = comment.match(/^(?:Section:\s*)?(.+)$/i);
      if (labelMatch){
        var label = labelMatch[1].trim();
        hr.classList.add('labeled');
        hr.setAttribute('data-label', label);
        // Remove the comment node
        prev.parentNode.removeChild(prev);
      }
    }
  });

  // Add anchor links to headings (GitHub-style)
  Array.from(target.querySelectorAll('h1, h2, h3, h4, h5, h6')).forEach(function(heading){
    if (heading.id){
      var anchor = document.createElement('a');
      anchor.className = 'heading-anchor';
      anchor.href = '#' + heading.id;
      anchor.setAttribute('aria-label', 'Anchor link for ' + heading.textContent);
      anchor.textContent = '#';
      heading.insertBefore(anchor, heading.firstChild);
    }
  });

  // Wrap tables in scrollable container
  Array.from(target.querySelectorAll('table')).forEach(function(table){
    if (!table.parentElement.classList.contains('table-wrapper')){
      var wrapper = document.createElement('div');
      wrapper.className = 'table-wrapper';
      table.parentNode.insertBefore(wrapper, table);
      wrapper.appendChild(table);
    }
  });

  // Add copy buttons to code blocks
  Array.from(target.querySelectorAll('pre code')).forEach(function(codeEl){
    var pre = codeEl.parentElement;
    if (!pre || pre.tagName !== 'PRE') return;

    var btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.textContent = 'Copy';
    btn.setAttribute('aria-label', 'Copy code to clipboard');
    btn.addEventListener('click', function(){
      var text = codeEl.textContent;
      if (navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(text).then(function(){
          btn.textContent = 'Copied!';
          btn.classList.add('copied');
          setTimeout(function(){
            btn.textContent = 'Copy';
            btn.classList.remove('copied');
          }, 2000);
        }).catch(function(err){
          btn.textContent = 'Error';
          setTimeout(function(){ btn.textContent = 'Copy'; }, 2000);
        });
      } else {
        // Fallback for older browsers
        var textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
          document.execCommand('copy');
          btn.textContent = 'Copied!';
          btn.classList.add('copied');
          setTimeout(function(){
            btn.textContent = 'Copy';
            btn.classList.remove('copied');
          }, 2000);
        } catch(err){
          btn.textContent = 'Error';
          setTimeout(function(){ btn.textContent = 'Copy'; }, 2000);
        }
        document.body.removeChild(textarea);
      }
    });
    pre.appendChild(btn);
  });
"""

    # Add syntax highlighting initialization
    if highlight_enabled and highlight_js:
        main_js += """
  // Initialize syntax highlighting
  if (window.hljs){
    Array.from(target.querySelectorAll('pre code')).forEach(function(block){
      try {
        window.hljs.highlightElement(block);
      } catch(e){
        console.warn('Highlight failed for block:', e);
      }
    });
  }
"""

    # Add line numbers
    if line_numbers:
        main_js += """
  // Add line numbers to code blocks (skip output blocks)
  Array.from(target.querySelectorAll('pre code')).forEach(function(codeEl){
    var pre = codeEl.parentElement;
    if (!pre || pre.tagName !== 'PRE') return;
    if (pre.classList.contains('line-numbers')) return; // Already has line numbers
    if (pre.classList.contains('output')) return; // Skip output blocks

    var code = codeEl.textContent;
    var lines = code.split('\\n');
    // Remove last empty line if exists
    if (lines[lines.length - 1] === '') lines.pop();

    var lineNumbersWrapper = document.createElement('span');
    lineNumbersWrapper.className = 'line-numbers-rows';
    lineNumbersWrapper.setAttribute('aria-hidden', 'true');

    for (var i = 0; i < lines.length; i++){
      lineNumbersWrapper.appendChild(document.createElement('span'));
    }

    pre.classList.add('line-numbers');
    pre.appendChild(lineNumbersWrapper);
  });
"""

    # Add KaTeX math rendering
    if katex_enabled and katex_js:
        main_js += """
  // Render LaTeX/Math with KaTeX
  if (window.katex){
    // Render display math ($$...$$)
    var displayMathRegex = /\\$\\$([^$]+)\\$\\$/g;
    // Render inline math ($...$)
    var inlineMathRegex = /\\$([^$]+)\\$/g;

    function renderMath(node){
      if (node.nodeType === 3){  // Text node
        var text = node.nodeValue;
        var hasDisplayMath = displayMathRegex.test(text);
        var hasInlineMath = inlineMathRegex.test(text);

        if (hasDisplayMath || hasInlineMath){
          displayMathRegex.lastIndex = 0;
          inlineMathRegex.lastIndex = 0;

          var frag = document.createDocumentFragment();
          var lastIdx = 0;

          // First handle display math
          text = text.replace(/\\$\\$([^$]+)\\$\\$/g, function(match, math, offset){
            if (offset > lastIdx){
              frag.appendChild(document.createTextNode(text.substring(lastIdx, offset)));
            }
            var span = document.createElement('span');
            span.className = 'math-display';
            span.style.display = 'block';
            span.style.textAlign = 'center';
            span.style.margin = '1rem 0';
            try {
              window.katex.render(math.trim(), span, { displayMode: true, throwOnError: false });
            } catch(e){
              span.textContent = match;
            }
            frag.appendChild(span);
            lastIdx = offset + match.length;
            return '';
          });

          if (lastIdx < text.length){
            var remaining = text.substring(lastIdx);
            // Handle inline math in remaining text
            remaining = remaining.replace(/\\$([^$]+)\\$/g, function(match, math){
              return '@@MATH@@' + math + '@@/MATH@@';
            });

            var parts = remaining.split(/(@@MATH@@[^@]+@@\\/MATH@@)/g);
            parts.forEach(function(part){
              if (part.startsWith('@@MATH@@')){
                var math = part.replace(/@@MATH@@(.+)@@\\/MATH@@/, '$1');
                var span = document.createElement('span');
                span.className = 'math-inline';
                try {
                  window.katex.render(math.trim(), span, { displayMode: false, throwOnError: false });
                } catch(e){
                  span.textContent = '$' + math + '$';
                }
                frag.appendChild(span);
              } else if (part){
                frag.appendChild(document.createTextNode(part));
              }
            });
          }

          node.parentNode.replaceChild(frag, node);
        }
      } else if (node.nodeType === 1 && node.tagName !== 'CODE' && node.tagName !== 'PRE'){
        var children = Array.from(node.childNodes);
        children.forEach(function(child){ renderMath(child); });
      }
    }

    renderMath(target);
  }
"""

    # Build script tags
    scripts = []
    scripts.append(f"  <script>\n{marked_js}\n  </script>")
    scripts.append(f"  <script>\n{purify_js}\n  </script>")

    if highlight_enabled and highlight_js:
        scripts.append(f"  <script>\n{highlight_js}\n  </script>")

    if katex_enabled and katex_js:
        scripts.append(f"  <script>\n{katex_js}\n  </script>")

    scripts.append(f"  <script>\n(function(){{\n{js_constants}\n{main_js}}})();\n  </script>")

    return "\n".join(scripts)

@st.cache_data(show_spinner="Building HTML...")
def build_html(
    md_text: str,
    meta: dict,
    vendor_libs: dict,
    toc_mode: str,
    toc_levels: str,
    back_to_top: bool,
    search_enabled: bool,
    collapsible_mode: str,
    start_collapsed: bool,
    theme_preset: str = "default",
    highlight_enabled: bool = False,
    highlight_theme: str = "github-light",
    katex_enabled: bool = False,
    line_numbers: bool = False,
    base_font_size: str = "100%",
    content_width: str = "900px"
) -> str:
    """Build complete HTML document."""

    safe_md = escape_for_script_tag(md_text)

    title = meta.get("title") or "Document"
    dtype = meta.get("doctype") or "Document"
    vers = meta.get("version") or "1.0"

    css = generate_css(toc_mode, back_to_top, search_enabled, collapsible_mode, theme_preset, highlight_enabled, highlight_theme, line_numbers, base_font_size, content_width)
    katex_css = vendor_libs.get("katex_css", "") if katex_enabled else ""
    toolbar = generate_toolbar(title, toc_mode, search_enabled, theme_preset)
    top_toc, sidebar_toc = generate_toc_containers(toc_mode)
    javascript = generate_javascript(vendor_libs, toc_mode, toc_levels, collapsible_mode, start_collapsed, back_to_top, search_enabled, highlight_enabled, katex_enabled, line_numbers)
    
    katex_css_tag = f"<style>\n{katex_css}\n</style>\n" if katex_css else ""

    # Set initial theme based on preset
    initial_theme = "dark" if theme_preset == "Dark" else "light"

    html = (
        "<!doctype html>\n"
        f"<html lang=\"en\" data-theme=\"{initial_theme}\">\n"
        "<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        f"<title>{escape_html(title)}</title>\n"
        f"<style>\n{css}\n</style>\n"
        f"{katex_css_tag}"
        "</head>\n"
        "<body>\n"
        "<a id=\"top\"></a>\n"
        "<a class=\"skip\" href=\"#content\">Skip to content</a>\n"
        f"{toolbar}\n"
        "<main id=\"content\" role=\"main\">\n"
        f"{top_toc}"
        f"{sidebar_toc}"
        "  <article id=\"md-target\"></article>\n"
        "  <script id=\"md-source\" type=\"text/markdown\">\n"
        f"{safe_md}\n"
        "  </script>\n"
        f"{javascript}\n"
        "</main>\n"
        "</body>\n"
        "</html>"
    )
    return html

# ---------- Streamlit UI ----------
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.title(APP_TITLE)
st.caption("Build a single, offline HTML from Markdown using Marked.js and DOMPurify. Includes syntax highlighting, math rendering, multiple themes, ToC, collapsible sections, and in-page search. Now supports mdBook projects!")

# Mode selection
mode = st.radio(
    "Input Mode",
    ["Single Markdown File", "mdBook Project"],
    horizontal=True,
    help="Choose single file mode or mdBook project mode for multi-chapter books"
)

uploaded_filename = None
md_text = ""
book_config = None
chapter_metadata = []

with st.container(border=True):
    st.subheader("Source")

    if mode == "Single Markdown File":
        uploaded = st.file_uploader("Upload a .md file", type=["md", "markdown"])
        if uploaded is not None:
            try:
                md_text = uploaded.read().decode("utf-8")
                uploaded_filename = uploaded.name
            except Exception as e:
                st.error(f"Failed to read file: {e}")
        md_text = st.text_area("Or paste Markdown", value=md_text, height=260, placeholder="# Title\n\n...")

    else:  # mdBook Project mode
        st.markdown("**Enter the path to your mdBook project directory:**")
        st.caption("The directory should contain `book.toml` and `src/SUMMARY.md`")

        project_path = st.text_input(
            "mdBook Project Path",
            placeholder="/path/to/your/mdbook/project",
            help="Absolute or relative path to mdBook project root directory"
        )

        if project_path:
            if os.path.exists(project_path) and os.path.isdir(project_path):
                try:
                    md_text, book_config, chapter_metadata = process_mdbook_project(project_path)
                    if md_text:
                        st.success(f"✓ Loaded mdBook project with {len(chapter_metadata)} chapters")
                        with st.expander("Preview combined markdown (first 500 chars)"):
                            st.code(md_text[:500] + "..." if len(md_text) > 500 else md_text, language="markdown")
                except Exception as e:
                    st.error(f"Failed to process mdBook project: {e}")
            else:
                st.error("Directory not found. Please enter a valid path.")

st.divider()

with st.container(border=True):
    st.subheader("Options")

    # Theme and appearance
    col1, col2 = st.columns([1, 1], gap="medium")
    with col1:
        theme_preset = st.selectbox(
            "Output Theme",
            ["Default", "GitHub", "Academic", "Minimal", "Dark"],
            index=0,
            help="Choose an overall theme for the generated HTML"
        )
        base_font_size = st.selectbox(
            "Base Font Size",
            ["Small (90%)", "Normal (100%)", "Large (110%)", "X-Large (125%)"],
            index=1,
            help="Adjust the base font size for readability"
        )
    with col2:
        content_width = st.selectbox(
            "Content Width",
            ["Narrow (700px)", "Normal (900px)", "Wide (1200px)", "Full (95vw)"],
            index=1,
            help="Maximum width of main content area"
        )
        search_enabled = st.toggle("Enable in-page search with highlight", value=True)

    st.divider()

    # Document structure
    col1, col2, col3 = st.columns([2, 2, 2], gap="large")
    with col1:
        toc_choice = st.radio("ToC placement", ["Top", "Sidebar (collapsible)", "None"], index=1, horizontal=True)
        back_to_top = st.toggle("Add Back to top link at end of each section", value=True)
    with col2:
        toc_levels_choice = st.radio("ToC heading levels", ["H2 only", "H2-H3", "H2-H3-H4"], index=0, horizontal=True)
        collapsible_choice = st.radio("Collapsible sections", ["None", "H2", "H2+H3"], index=2, horizontal=True)
    with col3:
        start_collapsed = st.toggle("Start sections collapsed", value=True, disabled=(collapsible_choice == "None"))

    st.divider()

    # Code and Math features
    col1, col2 = st.columns([1, 1], gap="medium")
    with col1:
        highlight_enabled = st.toggle("Enable syntax highlighting", value=True, help="Highlight code blocks with color syntax")
        highlight_theme = st.selectbox(
            "Syntax theme",
            ["github-light", "github-dark", "monokai", "atom-one-dark"],
            index=0,
            disabled=not highlight_enabled,
            help="Color theme for syntax highlighting"
        )
        line_numbers = st.toggle("Show line numbers in code blocks", value=False, help="Display line numbers on the left side of code blocks")
    with col2:
        katex_enabled = st.toggle("Enable Math/LaTeX rendering", value=True, help="Render $...$ and $$...$$ as mathematical equations")

# Map UI choices to internal values
toc_mode_map = {"Top": "top", "Sidebar (collapsible)": "sidebar", "None": "none"}
toc_levels_map = {"H2 only": "h2", "H2-H3": "h2h3", "H2-H3-H4": "h2h3h4"}
collapsible_mode_map = {"None": "none", "H2": "h2", "H2+H3": "h2h3"}
theme_preset_map = {"Default": "default", "GitHub": "github", "Academic": "academic", "Minimal": "minimal", "Dark": "dark"}
font_size_map = {"Small (90%)": "90%", "Normal (100%)": "100%", "Large (110%)": "110%", "X-Large (125%)": "125%"}
content_width_map = {"Narrow (700px)": "700px", "Normal (900px)": "900px", "Wide (1200px)": "1200px", "Full (95vw)": "95vw"}

toc_mode = toc_mode_map.get(toc_choice, "none")
toc_levels = toc_levels_map.get(toc_levels_choice, "h2")
collapsible_mode = collapsible_mode_map.get(collapsible_choice, "none")
theme_preset_value = theme_preset_map.get(theme_preset, "default")
base_font_size_value = font_size_map.get(base_font_size, "100%")
content_width_value = content_width_map.get(content_width, "900px")

st.divider()

build_col, preview_col = st.columns([1, 3], gap="large")
with build_col:
    st.subheader("Build")
    if st.button("Build HTML", type="primary", use_container_width=True):
        if not md_text.strip():
            st.warning("Provide Markdown via upload, paste, or mdBook project path.")
        else:
            try:
                vendor_libs = load_vendor_js(use_highlight=highlight_enabled, use_katex=katex_enabled)

                # Determine title based on mode
                if mode == "mdBook Project" and book_config:
                    final_title = book_config.get("book", {}).get("title", "Book")
                else:
                    # Auto-detect title from H1
                    final_title = "Document"
                    match = re.search(r'^\s*#\s+([^\n]+)', md_text, re.MULTILINE)
                    if match:
                        final_title = match.group(1).strip()

                meta = {
                    "title": final_title,
                    "doctype": "",
                    "version": "1.0",
                    "date": "",
                    "authors": "",
                    "summary": ""
                }

                html = build_html(
                    md_text, meta, vendor_libs,
                    toc_mode, toc_levels, back_to_top, search_enabled,
                    collapsible_mode, start_collapsed,
                    theme_preset_value, highlight_enabled, highlight_theme, katex_enabled,
                    line_numbers, base_font_size_value, content_width_value
                )

                # Determine default filename
                if mode == "mdBook Project":
                    default_name = sanitize_filename(final_title)
                elif uploaded_filename:
                    default_name = uploaded_filename.rsplit('.', 1)[0] + '.html'
                else:
                    default_name = sanitize_filename(final_title)

                # Store result in session state (Fix: disappearing download button)
                st.session_state["generated_html"] = html
                st.session_state["generated_name"] = default_name
                st.session_state["last_html"] = html
                st.success("HTML built successfully!")
            except Exception as e:
                st.error(f"Build failed: {e}")

    # Render download button outside the if block using session state
    # This ensures the button persists after clicking download
    if "generated_html" in st.session_state:
        st.download_button(
            "Download offline HTML",
            data=st.session_state["generated_html"].encode("utf-8"),
            file_name=st.session_state.get("generated_name", "document.html"),
            mime="text/html",
            use_container_width=True
        )

with preview_col:
    st.subheader("Preview")
    if "last_html" in st.session_state:
        st.components.v1.html(st.session_state["last_html"], height=650, scrolling=True)
    else:
        st.info("Build to see a live preview here.")
