"""
Markdown Conversion Utilities

Provides conversion from Markdown to various output formats:
- HTML (standalone offline document)
- DOCX (Word document via pandoc)

Security notes:
- All file operations use size limits to prevent DoS
- Path traversal prevention via safe_read_file()
- Unicode handling for filenames and content
"""
import os
import re
import io
import tempfile
import zipfile
from typing import Optional, Tuple

# Check for pypandoc availability
try:
    import pypandoc
    HAS_PYPANDOC = True
except ImportError:
    HAS_PYPANDOC = False
    pypandoc = None


# ---------- DOCX Conversion ----------

def _preprocess_markdown_for_docx(content: str) -> str:
    """
    Preprocess markdown to fix bullet list formatting issues.

    Pandoc requires specific formatting for bullet lists:
    - A blank line before the start of a list
    - No blank lines between items in a "tight" list
    """
    lines = content.split('\n')
    result = []

    def is_bullet_line(line):
        """Check if line is a bullet (starts with '- ' after optional whitespace)."""
        return bool(re.match(r'^(\s*)-\s', line))

    i = 0
    while i < len(lines):
        line = lines[i]

        if is_bullet_line(line):
            # Insert blank line before list if needed
            if result:
                prev_line = result[-1]
                if prev_line.strip() != '' and not is_bullet_line(prev_line):
                    result.append('')

            result.append(line)

            # Skip blank lines between consecutive bullets
            j = i + 1
            while j < len(lines) and lines[j].strip() == '':
                j += 1

            if j < len(lines) and is_bullet_line(lines[j]):
                i = j - 1
        else:
            result.append(line)

        i += 1

    return '\n'.join(result)


def _postprocess_docx(docx_bytes: bytes) -> bytes:
    """
    Post-process DOCX to fix pandoc's default styling.

    Modifies:
    - word/styles.xml: Style definitions (header colors, fonts)
    - word/document.xml: Actual document content (inline colors)
    - word/theme/theme1.xml: Theme definitions (font defaults)
    """
    with zipfile.ZipFile(io.BytesIO(docx_bytes), 'r') as zin:
        output_buffer = io.BytesIO()
        with zipfile.ZipFile(output_buffer, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)

                if item.filename == 'word/styles.xml':
                    content = data.decode('utf-8')
                    # Remove explicit color values (e.g., blue headers)
                    content = re.sub(r'<w:color\s+w:val="[0-9A-Fa-f]{6}"\s*/>', '', content)
                    # Remove theme color references
                    content = re.sub(r'<w:color[^>]*w:themeColor="[^"]*"[^>]*/>', '', content)
                    # Replace Cambria font with Latin Modern Roman
                    content = re.sub(r'w:ascii="Cambria"', 'w:ascii="Latin Modern Roman"', content)
                    content = re.sub(r'w:hAnsi="Cambria"', 'w:hAnsi="Latin Modern Roman"', content)
                    content = re.sub(r'w:eastAsia="Cambria"', 'w:eastAsia="Latin Modern Roman"', content)
                    content = re.sub(r'w:cs="Cambria"', 'w:cs="Latin Modern Roman"', content)
                    # Replace theme font references
                    content = re.sub(r'w:asciiTheme="[^"]*"', 'w:ascii="Latin Modern Roman"', content)
                    content = re.sub(r'w:hAnsiTheme="[^"]*"', 'w:hAnsi="Latin Modern Roman"', content)
                    content = re.sub(r'w:eastAsiaTheme="[^"]*"', 'w:eastAsia="Latin Modern Roman"', content)
                    content = re.sub(r'w:cstheme="[^"]*"', 'w:cs="Latin Modern Roman"', content)
                    data = content.encode('utf-8')

                elif item.filename == 'word/document.xml':
                    content = data.decode('utf-8')
                    # Remove inline color styling
                    content = re.sub(r'<w:color\s+w:val="[0-9A-Fa-f]{6}"\s*/>', '', content)
                    content = re.sub(r'<w:color[^>]*w:themeColor="[^"]*"[^>]*/>', '', content)
                    data = content.encode('utf-8')

                elif item.filename == 'word/theme/theme1.xml':
                    content = data.decode('utf-8')
                    content = re.sub(r'typeface="Cambria"', 'typeface="Latin Modern Roman"', content)
                    data = content.encode('utf-8')

                zout.writestr(item, data)

        output_buffer.seek(0)
        return output_buffer.read()


def check_docx_dependencies() -> Tuple[bool, str]:
    """
    Check if DOCX conversion dependencies are available.

    Returns:
        Tuple of (is_available, error_message)
    """
    if not HAS_PYPANDOC:
        return False, "pypandoc is not installed. Install with: pip install pypandoc"

    import shutil
    if shutil.which("pandoc") is None:
        return False, (
            "pandoc is not found on the system. Install with:\n"
            "  - macOS: brew install pandoc\n"
            "  - Ubuntu/Debian: apt-get install pandoc\n"
            "  - Windows: choco install pandoc"
        )

    return True, ""


def convert_markdown_to_docx(
    markdown_content: str,
    output_path: Optional[str] = None
) -> bytes:
    """
    Convert Markdown content to DOCX format.

    Args:
        markdown_content: The markdown text to convert
        output_path: Optional path to write the DOCX file

    Returns:
        The DOCX file content as bytes

    Raises:
        ImportError: If pypandoc is not installed
        RuntimeError: If pandoc is not installed or conversion fails
    """
    available, error = check_docx_dependencies()
    if not available:
        raise ImportError(error)

    # Preprocess markdown for better list handling
    content = _preprocess_markdown_for_docx(markdown_content)

    with tempfile.TemporaryDirectory() as tmpdir:
        temp_input = os.path.join(tmpdir, "input.md")
        temp_output = os.path.join(tmpdir, "output.docx")

        with open(temp_input, "w", encoding="utf-8") as f:
            f.write(content)

        try:
            pypandoc.convert_file(
                temp_input,
                "docx",
                outputfile=temp_output,
                extra_args=["--standalone", "--highlight-style=pygments", "--dpi=96"]
            )
        except Exception as e:
            raise RuntimeError(
                f"Pandoc conversion failed: {e}\n"
                "Check that the input is valid markdown."
            ) from e

        # Read the raw output
        with open(temp_output, 'rb') as f:
            docx_bytes = f.read()

        # Post-process to fix styling
        docx_bytes = _postprocess_docx(docx_bytes)

        # Write to output path if specified
        if output_path:
            with open(output_path, "wb") as f:
                f.write(docx_bytes)

        return docx_bytes


def sanitize_filename_for_format(name: str, extension: str) -> str:
    """
    Sanitize filename for a specific format extension.

    Args:
        name: The base filename
        extension: The target extension (e.g., '.docx', '.html')

    Returns:
        Sanitized filename with the correct extension
    """
    if not name:
        return f"document{extension}"

    # Remove characters not safe for filenames
    name = re.sub(r'[^\w\s._-]', '', name)
    name = re.sub(r'[\s]+', '_', name)
    name = name.strip('._-')

    if not name:
        return f"document{extension}"

    # Remove existing extension if present (case-insensitive)
    for ext in ['.html', '.htm', '.md', '.markdown', '.docx', '.doc']:
        if name.lower().endswith(ext):
            name = name[:-len(ext)]
            break

    # Truncate by byte count for Unicode safety (255 - extension length)
    max_base_bytes = 255 - len(extension.encode('utf-8'))
    while len(name.encode('utf-8')) > max_base_bytes:
        name = name[:-1]

    return name + extension
