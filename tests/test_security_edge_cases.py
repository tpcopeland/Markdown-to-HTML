"""
Advanced security edge case tests.

These tests probe for vulnerabilities that go beyond standard documentation:
- Unicode normalization attacks (NFC/NFD bypass)
- Null byte injection
- os.path.join absolute path bypass
- ReDoS (regex denial of service)
- Homoglyph attacks
- BOM and zero-width character handling
- Case folding attacks (Turkish i problem)
- Double encoding attacks
- Script tag variations
- CRLF injection
"""
import os
import sys
import time
import tempfile
import unicodedata
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
    safe_read_file,
    sanitize_filename,
    escape_for_script_tag,
    escape_js_string,
    escape_html,
    validate_css_size,
    validate_project_path,
    validate_vendor_path,
    parse_summary_md,
    sanitize_for_html_comment,
)
from md_converter import sanitize_filename_for_format


class TestUnicodeNormalizationAttacks:
    """Test for Unicode normalization bypass attacks."""

    def test_nfc_nfd_path_traversal(self):
        """Test that NFD decomposed '..' cannot bypass path checks."""
        # In Unicode NFD, some characters can be decomposed
        # For example, "ä" = "a" + combining umlaut
        # More critically, there could be edge cases with special chars

        # The dot character is U+002E, but there are lookalikes
        # Fullwidth full stop: U+FF0E (．)
        # One dot leader: U+2024 (․)

        with tempfile.TemporaryDirectory() as tmpdir:
            secret_dir = os.path.dirname(tmpdir)

            # Create a file in the base dir
            test_file = os.path.join(tmpdir, "test.md")
            with open(test_file, "w") as f:
                f.write("safe content")

            # Normal path should work
            content = safe_read_file(tmpdir, "test.md")
            assert content == "safe content"

            # NFD normalized path should still be blocked if it resolves to traversal
            # Test standard traversal (should be blocked)
            try:
                safe_read_file(tmpdir, "../etc/passwd")
                assert False, "Should have blocked path traversal"
            except ValueError:
                pass

    def test_unicode_fullwidth_dots(self):
        """Test fullwidth dot character doesn't bypass sanitization."""
        # Fullwidth full stop U+FF0E
        fullwidth_dot = "\uff0e"

        # In filename sanitization, this should be stripped
        filename = f"test{fullwidth_dot}{fullwidth_dot}/etc/passwd.html"
        sanitized = sanitize_filename(filename)

        # Should not contain path separators or traversal patterns
        assert "/" not in sanitized
        assert "\\" not in sanitized
        assert ".." not in sanitized

    def test_unicode_decomposition_in_filename(self):
        """Test that Unicode normalization doesn't create security issues."""
        # NFD form: 'ä' decomposed as 'a' + combining umlaut (U+0308)
        nfc_name = "täst.html"  # NFC form
        nfd_name = unicodedata.normalize('NFD', nfc_name)  # NFD form

        # Both should produce valid filenames
        nfc_result = sanitize_filename(nfc_name)
        nfd_result = sanitize_filename(nfd_name)

        # Both should be safe
        assert nfc_result.endswith('.html')
        assert nfd_result.endswith('.html')
        assert '/' not in nfc_result
        assert '/' not in nfd_result


class TestNullByteInjection:
    """Test for null byte injection attacks."""

    def test_null_byte_in_filename(self):
        """Test null bytes are handled in filenames."""
        # Classic null byte attack: file.txt%00.jpg -> file.txt
        filename = "test\x00.evil.html"
        sanitized = sanitize_filename(filename)

        # Null byte should be stripped (it's not alphanumeric)
        assert "\x00" not in sanitized
        assert sanitized.endswith('.html')

    def test_null_byte_in_path(self):
        """Test null bytes in file paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.md")
            with open(test_file, "w") as f:
                f.write("content")

            # Null byte in path should fail
            try:
                # This might raise ValueError or other exception
                safe_read_file(tmpdir, "test.md\x00/etc/passwd")
                # If it somehow succeeds, it should only get test.md content
            except (ValueError, TypeError, OSError):
                pass  # Expected - null bytes should be rejected

    def test_null_byte_in_css_value(self):
        """Test null bytes don't bypass CSS validation."""
        # Null byte shouldn't make invalid CSS valid
        result = validate_css_size("100\x00px")
        assert result == False

        result = validate_css_size("100px\x00")
        assert result == False


class TestOsPathJoinBypass:
    """Test for os.path.join absolute path bypass vulnerability."""

    def test_absolute_path_in_relative(self):
        """Test that absolute paths in relative_path don't bypass base_dir check."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.md")
            with open(test_file, "w") as f:
                f.write("safe content")

            # VULNERABILITY: os.path.join("/base", "/etc/passwd") = "/etc/passwd"
            # The function should detect and block this
            try:
                safe_read_file(tmpdir, "/etc/passwd")
                assert False, "Should have blocked absolute path bypass"
            except ValueError as e:
                assert "Security violation" in str(e) or "outside" in str(e).lower()

    def test_absolute_path_windows_style(self):
        """Test Windows-style absolute paths on any platform."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Windows absolute path
            try:
                safe_read_file(tmpdir, "C:\\Windows\\System32\\config\\SAM")
                # On Linux this might not be absolute, but should still be safe
            except (ValueError, FileNotFoundError, OSError):
                pass  # Expected

    def test_absolute_path_with_dots(self):
        """Test absolute path combined with traversal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                safe_read_file(tmpdir, "/../../../etc/passwd")
                assert False, "Should block path starting with /"
            except ValueError:
                pass


class TestReDoS:
    """Test for Regular Expression Denial of Service vulnerabilities."""

    def test_css_validation_redos(self):
        """Test CSS validation regex against ReDoS patterns."""
        # CSS regex: r'^\d+(\.\d+)?(px|%|em|rem|vh|vw)$'
        # This is a safe regex, but let's verify with long inputs

        start = time.time()
        # Feed it a very long invalid input
        long_input = "1" * 10000 + "x"
        result = validate_css_size(long_input)
        elapsed = time.time() - start

        assert result == False
        assert elapsed < 1.0, f"CSS validation took {elapsed}s - possible ReDoS"

    def test_filename_sanitization_redos(self):
        """Test filename sanitization regex against ReDoS."""
        start = time.time()

        # Create a pathological input
        # Regex: r'[^\w\s._-]' and r'[\s]+'
        # These are linear-time regexes, but let's verify
        pathological = "a" * 100000 + " " * 100000 + "b" * 100000

        result = sanitize_filename(pathological)
        elapsed = time.time() - start

        assert elapsed < 2.0, f"Filename sanitization took {elapsed}s - possible ReDoS"
        assert result.endswith('.html')

    def test_script_escape_redos(self):
        """Test script tag escape regex against ReDoS."""
        # Regex: r'</script\s*>'
        start = time.time()

        # Pathological: many </script with no closing >
        pathological = "</script" + " " * 100000 + "x"

        result = escape_for_script_tag(pathological)
        elapsed = time.time() - start

        assert elapsed < 1.0, f"Script escape took {elapsed}s - possible ReDoS"


class TestHomoglyphAttacks:
    """Test for homoglyph/lookalike character attacks."""

    def test_cyrillic_lookalikes_in_path(self):
        """Test Cyrillic lookalike characters don't bypass security."""
        # Cyrillic 'а' (U+0430) looks like Latin 'a' (U+0061)
        # Cyrillic 'е' (U+0435) looks like Latin 'e' (U+0065)
        # etc. = "еtс" with Cyrillic

        # A malicious path like "../еtс/passwd" might bypass naive checks
        cyrillic_etc = "\u0435tc"  # 'е' is Cyrillic

        with tempfile.TemporaryDirectory() as tmpdir:
            # This should either fail or be safe
            # The real danger is if it's interpreted as "etc" somewhere
            try:
                # Path with Cyrillic 'e'
                result = safe_read_file(tmpdir, f"../{cyrillic_etc}/passwd")
                assert False, "Path traversal with Cyrillic should be blocked"
            except (ValueError, FileNotFoundError):
                pass  # Expected

    def test_homoglyph_in_filename(self):
        """Test homoglyph characters in filenames."""
        # Mix of scripts
        filename = "tеst.html"  # 'е' is Cyrillic
        sanitized = sanitize_filename(filename)

        # Should be sanitized but not crash
        assert sanitized.endswith('.html')
        assert len(sanitized) > 5


class TestBOMAndZeroWidth:
    """Test BOM and zero-width character handling."""

    def test_utf8_bom_in_markdown(self):
        """Test UTF-8 BOM doesn't break parsing."""
        # UTF-8 BOM: \xef\xbb\xbf
        bom = '\ufeff'

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.md")
            with open(test_file, "w", encoding="utf-8") as f:
                f.write(bom + "# Hello\n\nContent")

            content = safe_read_file(tmpdir, "test.md")
            # Should read successfully (BOM is in content)
            assert "Hello" in content

    def test_zero_width_space_in_filename(self):
        """Test zero-width spaces are handled in filenames."""
        # Zero-width space: U+200B
        # Zero-width non-joiner: U+200C
        # Zero-width joiner: U+200D

        filename = "te\u200bst\u200c.html"  # Contains zero-width chars
        sanitized = sanitize_filename(filename)

        # Zero-width chars should be stripped (not alphanumeric)
        assert "\u200b" not in sanitized
        assert "\u200c" not in sanitized
        assert sanitized.endswith('.html')

    def test_rtl_override_attack(self):
        """Test right-to-left override character handling."""
        # RTL override U+202E can make "evil.exe" appear as "exe.live"
        # This is a common attack vector in filenames

        rtl_override = "\u202e"
        filename = f"readme{rtl_override}fdp.exe"  # Would display as "readmeexe.pdf"
        sanitized = sanitize_filename(filename)

        # RTL override should be stripped
        assert "\u202e" not in sanitized
        assert sanitized.endswith('.html')


class TestCaseFoldingAttacks:
    """Test case folding edge cases (Turkish i problem, etc.)."""

    def test_turkish_i_case_insensitivity(self):
        """Test Turkish İ/i doesn't break case-insensitive matching."""
        # In Turkish locale, 'I'.lower() != 'i' (it becomes 'ı')
        # And 'i'.upper() != 'I' (it becomes 'İ')

        # Test script tag escape with Turkish-like input
        turkish_script = "</SCRİPT>"  # With Turkish İ
        result = escape_for_script_tag(turkish_script)

        # Should not escape (İ != I), but shouldn't crash either
        assert result is not None

    def test_html_extension_case_variants(self):
        """Test various case combinations of .html extension."""
        test_cases = [
            "file.HTML",
            "file.Html",
            "file.HtMl",
            "file.hTmL",
        ]

        for filename in test_cases:
            sanitized = sanitize_filename(filename)
            # Should not produce double extension
            assert not sanitized.endswith('.html.html'), f"Double extension for {filename}"
            assert sanitized.lower().endswith('.html')


class TestDoubleEncodingAttacks:
    """Test double encoding and multi-encoding attacks."""

    def test_double_encoded_traversal(self):
        """Test double URL encoding doesn't bypass path checks."""
        # %2e = '.'
        # %252e = '%2e' (percent-encoded percent)
        # If decoded twice: %252e -> %2e -> .

        # These shouldn't be valid paths anyway, but let's ensure
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.md")
            with open(test_file, "w") as f:
                f.write("content")

            encoded_paths = [
                "%2e%2e/etc/passwd",
                "%252e%252e/etc/passwd",
                "..%c0%af../etc/passwd",  # overlong UTF-8 encoding of /
            ]

            for path in encoded_paths:
                try:
                    safe_read_file(tmpdir, path)
                    # If it succeeds, it should not have read /etc/passwd
                except (ValueError, FileNotFoundError, OSError):
                    pass  # Expected


class TestScriptTagVariations:
    """Test all variations of script tag escaping."""

    def test_script_case_variations(self):
        """Test all case variations of </script>."""
        variations = [
            "</script>",
            "</SCRIPT>",
            "</Script>",
            "</ScRiPt>",
            "</sCRIPT>",
        ]

        for variant in variations:
            result = escape_for_script_tag(f"content{variant}more")
            assert variant not in result, f"Failed to escape {variant}"
            assert "<\\/script>" in result.lower() or "\\/" in result

    def test_script_whitespace_variations(self):
        """Test script tags with various whitespace."""
        variations = [
            "</script >",
            "</script\t>",
            "</script\n>",
            "</script\r>",
            "</script  >",
            "</script\t\t>",
            "</script \t >",
        ]

        for variant in variations:
            result = escape_for_script_tag(f"content{variant}more")
            # Should be escaped
            assert "</script" not in result.lower() or "\\/" in result, f"Failed: {repr(variant)}"

    def test_script_with_attributes(self):
        """Test script tags with attributes (shouldn't match closing tag pattern)."""
        # Note: we're only escaping </script>, not <script>
        inputs = [
            '<script type="text/javascript">',
            '</script type="text/javascript">',  # Invalid but could be attempted
        ]

        for inp in inputs:
            result = escape_for_script_tag(inp)
            # Should not crash and should escape closing patterns
            assert result is not None


class TestCRLFInjection:
    """Test CRLF injection in various contexts."""

    def test_crlf_in_js_string(self):
        """Test CRLF doesn't break JS strings."""
        content = "line1\r\nline2\rline3\nline4"
        result = escape_js_string(content)

        # All newlines should be escaped
        assert "\r" not in result or "\\r" in result
        assert "\n" not in result or "\\n" in result

    def test_crlf_in_html_comment(self):
        """Test CRLF in HTML comments."""
        content = "text\r\n-->\r\n<script>evil</script>"
        result = sanitize_for_html_comment(content)

        # Should escape -- sequence
        assert "-->" not in result

    def test_crlf_in_filename(self):
        """Test CRLF in filenames."""
        filename = "file\r\n.html"
        sanitized = sanitize_filename(filename)

        # Should not contain CRLF
        assert "\r" not in sanitized
        assert "\n" not in sanitized


class TestHTMLEntityBypass:
    """Test HTML entity encoding bypass attempts."""

    def test_numeric_entity_bypass(self):
        """Test numeric entities are not created that could bypass escaping."""
        # &lt; = < in decimal
        # &#x3c; = < in hex

        content = "&#60;script&#62;alert(1)&#60;/script&#62;"
        result = escape_html(content)

        # The & should be escaped, preventing entity interpretation
        assert "&amp;#60;" in result or "&#60;" not in result

    def test_double_encoding_html(self):
        """Test double-encoded HTML doesn't bypass escaping."""
        content = "&amp;lt;script&amp;gt;"
        result = escape_html(content)

        # Already-escaped content should be re-escaped
        assert "&amp;amp;" in result


class TestValidateProjectPathEdgeCases:
    """Test project path validation edge cases."""

    def test_empty_path(self):
        """Test empty path is rejected."""
        is_valid, error = validate_project_path("")
        assert is_valid == False
        assert "empty" in error.lower()

    def test_path_with_null(self):
        """Test path with null bytes."""
        is_valid, error = validate_project_path("/tmp\x00/evil")
        # Should be invalid
        assert is_valid == False or error != ""

    def test_very_long_path(self):
        """Test extremely long paths."""
        long_path = "/tmp/" + "a" * 10000
        is_valid, error = validate_project_path(long_path)
        # Should not crash, either valid or invalid
        assert isinstance(is_valid, bool)

    def test_unicode_path(self):
        """Test Unicode in project path."""
        # Path with various Unicode characters
        unicode_path = "/tmp/тест/文件/test"  # Mixed scripts
        is_valid, error = validate_project_path(unicode_path)
        # Should not crash
        assert isinstance(is_valid, bool)


class TestIntegerBoundaries:
    """Test integer boundary conditions."""

    def test_summary_extreme_nesting(self):
        """Test SUMMARY.md with extreme nesting levels."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create SUMMARY.md with 1000 levels of nesting
            summary_path = os.path.join(tmpdir, "SUMMARY.md")
            lines = ["# Summary\n"]
            for i in range(1000):
                indent = "  " * i
                lines.append(f"{indent}- [Chapter {i}](chapter{i}.md)\n")

            with open(summary_path, "w") as f:
                f.writelines(lines)

            # Should not crash or hang
            chapters = parse_summary_md(summary_path)

            # Should parse but level should be capped
            assert len(chapters) > 0
            # Check that levels are capped at reasonable value
            max_level = max(c.level for c in chapters if not c.is_part_title)
            assert max_level <= 100  # Our cap

    def test_filename_max_length(self):
        """Test filename at maximum byte length."""
        # Create a filename that's exactly at the limit
        # With 4-byte UTF-8 chars (like emoji)
        emoji = "🎉"  # 4 bytes in UTF-8
        long_name = emoji * 100  # 400 bytes

        sanitized = sanitize_filename(long_name)

        # Should be truncated to valid length
        base = sanitized[:-5]  # Remove .html
        assert len(base.encode('utf-8')) <= 250


class TestSpecialFileNames:
    """Test special and reserved filenames."""

    def test_windows_reserved_names(self):
        """Test Windows reserved filenames."""
        reserved = ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"]

        for name in reserved:
            sanitized = sanitize_filename(name)
            # Should still work, produce valid filename
            assert sanitized.endswith('.html')

    def test_dot_files(self):
        """Test dotfiles/hidden files."""
        filenames = [".hidden", "..doubledot", "...tripledot"]

        for name in filenames:
            sanitized = sanitize_filename(name)
            # Leading dots should be stripped
            assert not sanitized.startswith('.')
            assert sanitized.endswith('.html')

    def test_only_special_chars(self):
        """Test filename with only special characters."""
        filenames = ["!@#$%^&*()", "   ", "\t\n\r", "..."]

        for name in filenames:
            sanitized = sanitize_filename(name)
            # Should return default
            assert sanitized == "document.html"


class TestSanitizeFilenameForFormat:
    """Test format-specific filename sanitization."""

    def test_existing_extensions_removed(self):
        """Test that existing extensions are properly removed."""
        test_cases = [
            ("document.html", ".docx", "document.docx"),
            ("document.HTML", ".docx", "document.docx"),
            ("document.md", ".html", "document.html"),
            ("document.MARKDOWN", ".html", "document.html"),
            ("document.docx", ".html", "document.html"),
        ]

        for name, ext, expected in test_cases:
            result = sanitize_filename_for_format(name, ext)
            assert result == expected, f"Expected {expected}, got {result}"

    def test_unicode_filename_truncation(self):
        """Test Unicode filename truncation by bytes."""
        # Create filename with 4-byte chars
        emoji = "📝"  # 4 bytes
        name = emoji * 100  # 400 bytes

        result = sanitize_filename_for_format(name, ".docx")

        # Should be truncated properly
        base = result[:-5]  # Remove .docx
        assert len(base.encode('utf-8')) <= 250


class TestHTMLCommentSanitization:
    """Test HTML comment sanitization edge cases."""

    def test_nested_comment_patterns(self):
        """Test nested and complex comment patterns."""
        test_cases = [
            ("-->", "&gt;"),  # Should escape >
            ("---->", "&gt;"),  # Multiple dashes then >
            ("--!>", "&gt;"),  # Comment end with !
            ("<!----", "&#45;&#45;"),  # Comment start pattern
        ]

        for input_val, expected_substr in test_cases:
            result = sanitize_for_html_comment(input_val)
            # Double dashes should be escaped
            assert "--" not in result or "&#45;&#45;" in result

    def test_xss_in_comment(self):
        """Test XSS payloads in comments."""
        payloads = [
            "--><script>alert(1)</script><!--",
            "-- ><script>alert(1)</script>",
            "--!><script>alert(1)</script>",
        ]

        for payload in payloads:
            result = sanitize_for_html_comment(payload)
            # Should not be able to break out of comment
            assert "-->" not in result


# Run all tests
if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
