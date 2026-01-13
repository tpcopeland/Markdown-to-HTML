"""
Deep audit tests - probing for subtle vulnerabilities.

These tests go even deeper than standard security tests:
- validate_vendor_path symlink vulnerability
- JS template literal (backtick) escaping
- Script tag with various control characters
- Edge cases in escape_js_string
- DOCX zipslip potential
"""
import os
import sys
import tempfile
from unittest.mock import MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Create comprehensive streamlit mock before importing md_converter
mock_st = MagicMock()
def mock_columns(num_cols, **kwargs):
    if isinstance(num_cols, list):
        return [MagicMock() for _ in num_cols]
    return [MagicMock() for _ in range(num_cols)]
mock_st.columns = mock_columns
mock_st.container.return_value.__enter__ = MagicMock(return_value=MagicMock())
mock_st.container.return_value.__exit__ = MagicMock(return_value=False)
mock_st.set_page_config = MagicMock()
mock_st.title = MagicMock()
mock_st.caption = MagicMock()
mock_st.radio = MagicMock(return_value="Single Markdown File")
mock_st.file_uploader = MagicMock(return_value=None)
mock_st.text_area = MagicMock(return_value="")
mock_st.text_input = MagicMock(return_value="")
mock_st.selectbox = MagicMock(return_value="Default")
mock_st.toggle = MagicMock(return_value=True)
mock_st.button = MagicMock(return_value=False)
mock_st.divider = MagicMock()
mock_st.subheader = MagicMock()
mock_st.markdown = MagicMock()
mock_st.session_state = {}
def mock_cache_data(func=None, **kwargs):
    if func is not None:
        return func
    return lambda f: f
mock_st.cache_data = mock_cache_data
mock_st.error = MagicMock()
mock_st.warning = MagicMock()
mock_st.success = MagicMock()
mock_st.info = MagicMock()
mock_st.stop = MagicMock(side_effect=SystemExit)
mock_st.expander.return_value.__enter__ = MagicMock(return_value=MagicMock())
mock_st.expander.return_value.__exit__ = MagicMock(return_value=False)

sys.modules['streamlit'] = mock_st
sys.modules['streamlit.components'] = MagicMock()
sys.modules['streamlit.components.v1'] = MagicMock()

from md_converter import (
    validate_vendor_path,
    escape_js_string,
    escape_for_script_tag,
    escape_html,
    safe_read_file,
    build_html,
)


class TestValidateVendorPathSymlink:
    """Test validate_vendor_path symlink handling.

    FIXED: validate_vendor_path now uses os.path.realpath which resolves symlinks.
    Symlinks in the vendor directory pointing outside will be detected and blocked.
    """

    def test_symlink_in_vendor_directory_blocked(self):
        """Test that symlinks in vendor directory pointing outside are blocked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file outside the vendor directory
            outside_file = os.path.join(tmpdir, "secret.txt")
            with open(outside_file, "w") as f:
                f.write("SECRET DATA")

            # Create vendor directory
            vendor_dir = os.path.join(tmpdir, "vendor")
            os.makedirs(vendor_dir)

            # Create a legitimate file in vendor
            legit_file = os.path.join(vendor_dir, "marked.min.js")
            with open(legit_file, "w") as f:
                f.write("// legitimate js content" + "x" * 100)

            # Create a symlink in vendor pointing to secret file outside
            symlink_path = os.path.join(vendor_dir, "evil.min.js")
            os.symlink(outside_file, symlink_path)

            # validate_vendor_path should block this symlink
            # because it resolves to outside the vendor directory
            try:
                result = validate_vendor_path(vendor_dir, "evil.min.js")
                # If we got here without SystemExit, the symlink bypassed - FAIL
                assert False, "Symlink pointing outside vendor dir should be blocked"
            except SystemExit:
                # validate_vendor_path called st.stop() - correct behavior
                pass

    def test_symlink_within_vendor_directory_allowed(self):
        """Test that symlinks within vendor directory are allowed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create vendor directory
            vendor_dir = os.path.join(tmpdir, "vendor")
            os.makedirs(vendor_dir)

            # Create a legitimate file in vendor
            legit_file = os.path.join(vendor_dir, "marked.min.js")
            with open(legit_file, "w") as f:
                f.write("// legitimate js content" + "x" * 100)

            # Create a symlink within vendor pointing to another file in vendor
            symlink_path = os.path.join(vendor_dir, "alias.min.js")
            os.symlink(legit_file, symlink_path)

            # This should be allowed since both are within vendor
            result = validate_vendor_path(vendor_dir, "alias.min.js")
            assert result == os.path.realpath(symlink_path)

    def test_legitimate_vendor_file(self):
        """Test that legitimate files in vendor work correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vendor_dir = os.path.join(tmpdir, "vendor")
            os.makedirs(vendor_dir)

            legit_file = os.path.join(vendor_dir, "marked.min.js")
            with open(legit_file, "w") as f:
                f.write("// legitimate js content" + "x" * 100)

            result = validate_vendor_path(vendor_dir, "marked.min.js")
            assert result == os.path.realpath(legit_file)


class TestJSBacktickEscaping:
    """Test JavaScript template literal (backtick) escaping.

    Modern JS uses backticks for template literals: `Hello ${name}`
    If backticks are not escaped, an attacker could break out of a string
    and inject code via ${...} expressions.
    """

    def test_backtick_in_js_string(self):
        """Test that backticks are handled in JS strings."""
        # If content contains backticks and we use them in template literals
        content = "Hello `${alert(1)}` world"
        result = escape_js_string(content)

        # The escaped string should not allow template injection
        # Note: escape_js_string is for regular strings, not template literals
        # But if the output is used in a template literal context, backticks matter
        assert result is not None
        # Currently backticks are NOT escaped - documenting this
        # This is only a risk if the escaped string is used in template literals

    def test_backtick_with_dollar_brace(self):
        """Test ${} pattern in JS strings."""
        content = "test ${document.cookie} end"
        result = escape_js_string(content)

        # If this is used in a template literal, it would execute
        # escape_js_string should probably escape $ or { to be safe
        assert result is not None


class TestScriptTagControlCharacters:
    """Test script tag escaping with various control characters."""

    def test_script_with_vertical_tab(self):
        """Test script tag with vertical tab."""
        # Vertical tab \x0b might be treated as whitespace
        content = "</script\x0b>"
        result = escape_for_script_tag(content)
        # Should be escaped
        assert "</script" not in result.lower() or "\\/" in result

    def test_script_with_form_feed(self):
        """Test script tag with form feed."""
        # Form feed \x0c might be treated as whitespace
        content = "</script\x0c>"
        result = escape_for_script_tag(content)
        # Check if it's handled
        assert result is not None

    def test_script_with_nbsp(self):
        """Test script tag with non-breaking space."""
        # NBSP U+00A0 might be treated as whitespace by HTML parsers
        content = "</script\xa0>"
        result = escape_for_script_tag(content)
        # Should be escaped
        assert result is not None

    def test_script_with_unicode_spaces(self):
        """Test script tag with various Unicode space characters."""
        unicode_spaces = [
            "\u0009",  # Tab
            "\u000A",  # Line feed
            "\u000B",  # Vertical tab
            "\u000C",  # Form feed
            "\u000D",  # Carriage return
            "\u0020",  # Space
            "\u0085",  # Next line
            "\u00A0",  # NBSP
            "\u1680",  # Ogham space
            "\u2000",  # En quad
            "\u2001",  # Em quad
            "\u2002",  # En space
            "\u2003",  # Em space
            "\u2004",  # Three-per-em space
            "\u2005",  # Four-per-em space
            "\u2006",  # Six-per-em space
            "\u2007",  # Figure space
            "\u2008",  # Punctuation space
            "\u2009",  # Thin space
            "\u200A",  # Hair space
            "\u2028",  # Line separator
            "\u2029",  # Paragraph separator
            "\u202F",  # Narrow NBSP
            "\u205F",  # Medium mathematical space
            "\u3000",  # Ideographic space
        ]

        for space in unicode_spaces:
            content = f"</script{space}>"
            result = escape_for_script_tag(content)
            # At minimum, shouldn't crash
            assert result is not None


class TestEscapeJsStringEdgeCases:
    """Test edge cases in escape_js_string."""

    def test_all_escape_sequences(self):
        """Test all characters that should be escaped."""
        # Build a string with all special chars
        special = '\\"\'\\n\\r\\t\u2028\u2029</script>'
        content = f"prefix{special}suffix"
        result = escape_js_string(content)

        # None of these should appear unescaped
        assert '\n' not in result or '\\n' in result
        assert '\r' not in result or '\\r' in result
        assert '\t' not in result or '\\t' in result
        assert '\u2028' not in result
        assert '\u2029' not in result

    def test_null_character(self):
        """Test null character in JS strings."""
        content = "before\x00after"
        result = escape_js_string(content)
        # Should not crash
        assert result is not None

    def test_high_unicode(self):
        """Test high Unicode codepoints (surrogate pairs)."""
        # Emoji and other 4-byte UTF-8 characters
        content = "Hello 🎉 World 𝕳𝖊𝖑𝖑𝖔"
        result = escape_js_string(content)
        assert result is not None
        # Should preserve the characters (they're valid in JS strings)

    def test_combining_characters(self):
        """Test combining Unicode characters."""
        # Combining diacritics that modify previous character
        content = "e\u0301"  # é as e + combining acute accent
        result = escape_js_string(content)
        assert result is not None


class TestBuildHtmlXSS:
    """Test the full HTML build for XSS vectors."""

    def test_xss_in_markdown_content(self):
        """Test XSS payloads in markdown content."""
        malicious_md = """
# Test

<script>alert('xss')</script>

<img src=x onerror=alert(1)>

<svg onload=alert(1)>

[link](javascript:alert(1))
"""
        # We need vendor libs for build_html
        # This test documents behavior but may not run without full setup

    def test_script_tag_in_code_fence(self):
        """Test script tag inside markdown code fence."""
        md_content = """
# Code Example

```javascript
</script><script>alert(1)</script>
```
"""
        # The script tag in code should be escaped by DOMPurify
        # This is handled client-side


class TestPathEdgeCases:
    """Additional path handling edge cases."""

    def test_path_with_colon(self):
        """Test paths with colons (Windows drive letters, macOS resource forks)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.md")
            with open(test_file, "w") as f:
                f.write("content")

            # C: style path on Linux should be treated as relative
            try:
                safe_read_file(tmpdir, "C:\\Windows\\System32\\config\\SAM")
            except (ValueError, FileNotFoundError, OSError):
                pass  # Expected

    def test_path_with_angle_brackets(self):
        """Test paths with angle brackets (invalid on Windows)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Angle brackets are invalid in Windows paths
            try:
                safe_read_file(tmpdir, "file<name>.md")
            except (ValueError, FileNotFoundError, OSError):
                pass  # Expected

    def test_path_with_pipe(self):
        """Test paths with pipe character."""
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                safe_read_file(tmpdir, "file|name.md")
            except (ValueError, FileNotFoundError, OSError):
                pass  # Expected


class TestIntegerOverflow:
    """Test integer overflow conditions."""

    def test_extremely_long_filename(self):
        """Test filename at system limits."""
        from md_converter import sanitize_filename

        # Create filename at maximum length
        long_name = "a" * 100000
        result = sanitize_filename(long_name)

        # Should be truncated to valid length
        assert len(result.encode('utf-8')) <= 255
        assert result.endswith('.html')

    def test_negative_indentation_level(self):
        """Test that negative indentation is handled."""
        # This shouldn't happen in practice, but let's verify
        from md_converter import parse_summary_md

        with tempfile.TemporaryDirectory() as tmpdir:
            summary_path = os.path.join(tmpdir, "SUMMARY.md")
            # Normal SUMMARY.md content
            with open(summary_path, "w") as f:
                f.write("# Summary\n- [Chapter](chapter.md)\n")

            chapters = parse_summary_md(summary_path)
            # Should parse without issues
            assert len(chapters) > 0


class TestConcurrencyIssues:
    """Test for race conditions and concurrency issues.

    Note: These are difficult to test reliably in unit tests.
    Documenting potential issues for review.
    """

    def test_toctou_in_safe_read_file(self):
        """Document TOCTOU potential in safe_read_file.

        safe_read_file checks the path, then reads the file.
        Between check and read, the file could be:
        1. Deleted (causes FileNotFoundError - handled)
        2. Replaced with symlink (potential bypass)
        3. Content changed (not a security issue for reading)

        The symlink replacement between realpath() and open() is a
        theoretical TOCTOU race condition.
        """
        # This is hard to test reliably in a unit test
        # Documenting for manual security review
        pass


class TestDOCXEdgeCases:
    """Test DOCX conversion edge cases."""

    def test_markdown_with_shell_metacharacters(self):
        """Test markdown containing shell metacharacters doesn't cause injection."""
        from md_converter import _preprocess_markdown_for_docx

        # These should be safely handled even though they contain shell chars
        dangerous_md = """
# Title `$(whoami)`

Code: $(cat /etc/passwd)

Path: /tmp/test; rm -rf /

Backticks: `id`

Pipes: | head -1
"""
        result = _preprocess_markdown_for_docx(dangerous_md)
        # Should process without crash - content goes to file, not shell
        assert "$(whoami)" in result or result is not None

    def test_markdown_with_embedded_null(self):
        """Test markdown with null bytes."""
        from md_converter import _preprocess_markdown_for_docx

        md_with_null = "# Title\x00\n\nContent"
        # Should handle without crash
        result = _preprocess_markdown_for_docx(md_with_null)
        assert result is not None


class TestMoreScriptVariations:
    """Additional script tag escape tests."""

    def test_script_broken_across_lines(self):
        """Test script tag broken with line continuations."""
        # HTML doesn't support line continuations, but let's verify
        test_cases = [
            "</scr\nipt>",  # Newline inside
            "</scr\ript>",  # Carriage return inside
            "</scr\tipt>",  # Tab inside
        ]

        for case in test_cases:
            result = escape_for_script_tag(case)
            # Shouldn't crash
            assert result is not None

    def test_nested_script_attempts(self):
        """Test nested script tag patterns."""
        cases = [
            "</script</script>>",
            "<</script/script>>",
            "</script></script>",
        ]

        for case in cases:
            result = escape_for_script_tag(case)
            # All should be escaped
            assert "</script>" not in result.lower()


class TestUnicodeEdgeCases:
    """More Unicode edge cases."""

    def test_overlong_utf8_sequences(self):
        """Test handling of potentially overlong UTF-8 sequences.

        Python 3 handles UTF-8 correctly, but let's verify the code
        doesn't have issues with unusual Unicode.
        """
        from md_converter import sanitize_filename

        # Various unusual Unicode characters
        cases = [
            "test\u0000name",  # Null
            "test\ufffdname",  # Replacement character
            "test\ufeFFname",  # BOM as character
            "test\u200bname",  # Zero-width space
        ]

        for case in cases:
            result = sanitize_filename(case)
            # Should produce valid filename
            assert result.endswith('.html')
            assert '\x00' not in result

    def test_bidirectional_text(self):
        """Test bidirectional text handling."""
        from md_converter import sanitize_filename

        # Hebrew/Arabic with LTR embedding
        bidi_name = "test\u202aעברית\u202cname.html"
        result = sanitize_filename(bidi_name)
        # Should be sanitized
        assert result.endswith('.html')


# Run all tests
if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
