"""
Unit tests for md_converter.py

Tests security features, input validation, and core functionality.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Create comprehensive streamlit mock before importing md_converter
mock_st = MagicMock()
# columns() returns variable number based on input
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
# cache_data can be used as @st.cache_data or @st.cache_data(...)
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

import md_converter


class TestEscapeHtml(unittest.TestCase):
    """Test HTML escaping function."""

    def test_escape_html_basic(self):
        """Test basic HTML character escaping."""
        self.assertEqual(md_converter.escape_html("<script>"), "&lt;script&gt;")
        self.assertEqual(md_converter.escape_html("a & b"), "a &amp; b")
        self.assertEqual(md_converter.escape_html('"test"'), "&quot;test&quot;")
        self.assertEqual(md_converter.escape_html("'test'"), "&#x27;test&#x27;")

    def test_escape_html_empty(self):
        """Test empty string handling."""
        self.assertEqual(md_converter.escape_html(""), "")
        self.assertEqual(md_converter.escape_html(None), "")

    def test_escape_html_combined(self):
        """Test combined special characters."""
        input_str = '<a href="test">click & go</a>'
        expected = "&lt;a href=&quot;test&quot;&gt;click &amp; go&lt;/a&gt;"
        self.assertEqual(md_converter.escape_html(input_str), expected)


class TestEscapeJsString(unittest.TestCase):
    """Test JavaScript string escaping function."""

    def test_escape_js_string_basic(self):
        """Test basic JS escaping."""
        self.assertEqual(md_converter.escape_js_string("test's"), "test\\'s")
        self.assertEqual(md_converter.escape_js_string('test"s'), 'test\\"s')
        self.assertEqual(md_converter.escape_js_string("line\nbreak"), "line\\nbreak")

    def test_escape_js_string_script_tag(self):
        """Test script tag escaping."""
        self.assertEqual(md_converter.escape_js_string("</script>"), "<\\/script>")

    def test_escape_js_string_empty(self):
        """Test empty string handling."""
        self.assertEqual(md_converter.escape_js_string(""), "")
        self.assertEqual(md_converter.escape_js_string(None), "")


class TestEscapeForScriptTag(unittest.TestCase):
    """Test script tag content escaping."""

    def test_escape_script_tag_closing(self):
        """Test closing script tag escaping."""
        self.assertEqual(md_converter.escape_for_script_tag("</script>"), "<\\/script>")
        # Case-insensitive replacement - all variants become lowercase escaped
        # This is safe because the browser won't close the tag regardless of case
        result_upper = md_converter.escape_for_script_tag("</SCRIPT>")
        self.assertIn("<\\/", result_upper)
        result_mixed = md_converter.escape_for_script_tag("</Script>")
        self.assertIn("<\\/", result_mixed)

    def test_escape_script_tag_empty(self):
        """Test empty string handling."""
        self.assertEqual(md_converter.escape_for_script_tag(""), "")
        self.assertEqual(md_converter.escape_for_script_tag(None), "")


class TestSanitizeForHtmlComment(unittest.TestCase):
    """Test HTML comment sanitization."""

    def test_sanitize_double_dash(self):
        """Test double dash escaping."""
        self.assertEqual(md_converter.sanitize_for_html_comment("--"), "&#45;&#45;")
        self.assertEqual(md_converter.sanitize_for_html_comment("test--value"), "test&#45;&#45;value")

    def test_sanitize_comment_breakout(self):
        """Test comment breakout prevention."""
        # This would normally break out of a comment
        result = md_converter.sanitize_for_html_comment("-->")
        self.assertNotIn("-->", result)

    def test_sanitize_empty(self):
        """Test empty string handling."""
        self.assertEqual(md_converter.sanitize_for_html_comment(""), "")
        self.assertEqual(md_converter.sanitize_for_html_comment(None), "")


class TestValidateCssSize(unittest.TestCase):
    """Test CSS size validation."""

    def test_validate_css_size_valid(self):
        """Test valid CSS sizes."""
        self.assertTrue(md_converter.validate_css_size("100%"))
        self.assertTrue(md_converter.validate_css_size("16px"))
        self.assertTrue(md_converter.validate_css_size("1.5em"))
        self.assertTrue(md_converter.validate_css_size("2rem"))
        self.assertTrue(md_converter.validate_css_size("100vh"))
        self.assertTrue(md_converter.validate_css_size("50vw"))

    def test_validate_css_size_invalid(self):
        """Test invalid CSS sizes."""
        self.assertFalse(md_converter.validate_css_size(""))
        self.assertFalse(md_converter.validate_css_size("abc"))
        self.assertFalse(md_converter.validate_css_size("100"))
        self.assertFalse(md_converter.validate_css_size("100pt"))
        self.assertFalse(md_converter.validate_css_size("url(evil.css)"))
        self.assertFalse(md_converter.validate_css_size("100%; injection"))

    def test_validate_css_size_injection(self):
        """Test CSS injection attempts."""
        self.assertFalse(md_converter.validate_css_size("100%}body{color:red"))
        self.assertFalse(md_converter.validate_css_size("expression(alert())"))


class TestSanitizeFilename(unittest.TestCase):
    """Test filename sanitization."""

    def test_sanitize_filename_basic(self):
        """Test basic filename sanitization."""
        self.assertEqual(md_converter.sanitize_filename("test"), "test.html")
        self.assertEqual(md_converter.sanitize_filename("test.html"), "test.html")

    def test_sanitize_filename_special_chars(self):
        """Test special character removal."""
        self.assertEqual(md_converter.sanitize_filename("test<>file"), "testfile.html")
        self.assertEqual(md_converter.sanitize_filename("test/file"), "testfile.html")

    def test_sanitize_filename_empty(self):
        """Test empty filename handling."""
        self.assertEqual(md_converter.sanitize_filename(""), "document.html")
        self.assertEqual(md_converter.sanitize_filename(None), "document.html")

    def test_sanitize_filename_path_traversal(self):
        """Test path traversal prevention."""
        result = md_converter.sanitize_filename("../../../etc/passwd")
        self.assertNotIn("..", result)
        self.assertNotIn("/", result)


class TestValidateDate(unittest.TestCase):
    """Test date validation."""

    def test_validate_date_valid(self):
        """Test valid ISO dates."""
        self.assertTrue(md_converter.validate_date("2024-01-15"))
        self.assertTrue(md_converter.validate_date(""))  # Empty is valid

    def test_validate_date_invalid(self):
        """Test invalid dates."""
        self.assertFalse(md_converter.validate_date("2024/01/15"))
        self.assertFalse(md_converter.validate_date("01-15-2024"))
        self.assertFalse(md_converter.validate_date("not-a-date"))


class TestValidateVendorPath(unittest.TestCase):
    """Test vendor path validation."""

    def setUp(self):
        """Set up test fixtures."""
        self.vendor_dir = md_converter.VENDOR_DIR

    def test_validate_vendor_path_valid(self):
        """Test valid vendor filenames."""
        # Should not raise
        result = md_converter.validate_vendor_path(self.vendor_dir, "marked.umd.min.js")
        self.assertTrue(result.endswith("marked.umd.min.js"))

    def test_validate_vendor_path_traversal(self):
        """Test path traversal prevention."""
        # These should trigger st.error and st.stop (mocked)
        with self.assertRaises(SystemExit):
            md_converter.validate_vendor_path(self.vendor_dir, "../secret.txt")

    def test_validate_vendor_path_dotfile(self):
        """Test dotfile prevention."""
        with self.assertRaises(SystemExit):
            md_converter.validate_vendor_path(self.vendor_dir, ".hidden")


class TestValidateProjectPath(unittest.TestCase):
    """Test project path validation."""

    def test_validate_project_path_valid(self):
        """Test valid project paths."""
        is_valid, error = md_converter.validate_project_path("/home/user/project")
        self.assertTrue(is_valid)
        self.assertEqual(error, "")

    def test_validate_project_path_traversal(self):
        """Test path traversal prevention."""
        is_valid, error = md_converter.validate_project_path("../../../etc")
        self.assertFalse(is_valid)
        self.assertIn("traversal", error.lower())

    def test_validate_project_path_sensitive(self):
        """Test sensitive directory blocking."""
        sensitive_dirs = ["/etc", "/var", "/root", "/sys", "/proc", "/dev", "/boot"]
        for path in sensitive_dirs:
            is_valid, error = md_converter.validate_project_path(path)
            self.assertFalse(is_valid, f"Should block {path}")

    def test_validate_project_path_empty(self):
        """Test empty path handling."""
        is_valid, error = md_converter.validate_project_path("")
        self.assertFalse(is_valid)


class TestSafeReadFile(unittest.TestCase):
    """Test safe file reading."""

    def test_safe_read_file_traversal(self):
        """Test path traversal prevention."""
        with self.assertRaises(ValueError) as context:
            md_converter.safe_read_file("/tmp/test", "../../../etc/passwd")
        self.assertIn("Security violation", str(context.exception))


class TestGetThemeCss(unittest.TestCase):
    """Test theme CSS generation."""

    def test_get_theme_css_valid_themes(self):
        """Test valid theme names."""
        themes = ["default", "github", "academic", "minimal", "dark"]
        for theme in themes:
            result = md_converter.get_theme_css(theme)
            self.assertIsInstance(result, list)
            self.assertGreater(len(result), 0)

    def test_get_theme_css_invalid(self):
        """Test invalid theme falls back to default."""
        result = md_converter.get_theme_css("nonexistent")
        default = md_converter.get_theme_css("default")
        self.assertEqual(result, default)


class TestGenerateCss(unittest.TestCase):
    """Test CSS generation."""

    def test_generate_css_valid_sizes(self):
        """Test CSS generation with valid sizes."""
        css = md_converter.generate_css(
            toc_mode="top",
            back_to_top=True,
            search_enabled=True,
            collapsible_mode="h2",
            theme_preset="default",
            highlight_enabled=False,
            highlight_theme="github-light",
            line_numbers=False,
            base_font_size="100%",
            content_width="900px"
        )
        self.assertIn("--base-font-size:100%", css)
        self.assertIn("--content-width:900px", css)

    def test_generate_css_invalid_sizes_default(self):
        """Test CSS generation with invalid sizes uses defaults."""
        css = md_converter.generate_css(
            toc_mode="top",
            back_to_top=True,
            search_enabled=True,
            collapsible_mode="h2",
            theme_preset="default",
            highlight_enabled=False,
            highlight_theme="github-light",
            line_numbers=False,
            base_font_size="invalid",
            content_width="invalid"
        )
        # Should use default values
        self.assertIn("--base-font-size:100%", css)
        self.assertIn("--content-width:900px", css)


class TestGenerateToolbar(unittest.TestCase):
    """Test toolbar generation."""

    def test_generate_toolbar_escapes_title(self):
        """Test that title is properly escaped."""
        toolbar = md_converter.generate_toolbar(
            title='<script>alert("xss")</script>',
            toc_mode="none",
            search_enabled=False,
            theme_preset="default"
        )
        self.assertNotIn("<script>", toolbar)
        self.assertIn("&lt;script&gt;", toolbar)

    def test_generate_toolbar_dark_theme_no_toggle(self):
        """Test dark theme preset doesn't show theme toggle."""
        toolbar = md_converter.generate_toolbar(
            title="Test",
            toc_mode="none",
            search_enabled=False,
            theme_preset="dark"
        )
        self.assertNotIn("themeToggle", toolbar)

    def test_generate_toolbar_light_theme_has_toggle(self):
        """Test non-dark theme shows theme toggle."""
        toolbar = md_converter.generate_toolbar(
            title="Test",
            toc_mode="none",
            search_enabled=False,
            theme_preset="default"
        )
        self.assertIn("themeToggle", toolbar)


class TestChapterParsing(unittest.TestCase):
    """Test mdBook chapter parsing."""

    def test_chapter_creation(self):
        """Test Chapter class creation."""
        chapter = md_converter.Chapter(
            title="Test Chapter",
            path="test.md",
            level=0,
            is_draft=False
        )
        self.assertEqual(chapter.title, "Test Chapter")
        self.assertEqual(chapter.path, "test.md")
        self.assertEqual(chapter.level, 0)
        self.assertFalse(chapter.is_draft)

    def test_chapter_repr(self):
        """Test Chapter string representation."""
        chapter = md_converter.Chapter(title="Test", path="test.md", level=1)
        repr_str = repr(chapter)
        self.assertIn("Test", repr_str)
        self.assertIn("test.md", repr_str)


class TestSanitizeFilenameExtended(unittest.TestCase):
    """Extended tests for filename sanitization including truncation."""

    def test_sanitize_filename_long_truncation(self):
        """Test that long filenames are properly truncated while preserving .html extension."""
        # Very long filename should be truncated to 255 chars max with .html preserved
        long_name = "a" * 300
        result = md_converter.sanitize_filename(long_name)
        self.assertEqual(len(result), 255)
        self.assertTrue(result.endswith(".html"))
        self.assertEqual(result, "a" * 250 + ".html")

    def test_sanitize_filename_boundary_cases(self):
        """Test boundary cases for filename length."""
        # Exactly 250 chars - should become 255 with .html
        name_250 = "b" * 250
        result = md_converter.sanitize_filename(name_250)
        self.assertEqual(len(result), 255)
        self.assertTrue(result.endswith(".html"))

        # 251 chars - should be truncated to 250 + .html = 255
        name_251 = "c" * 251
        result = md_converter.sanitize_filename(name_251)
        self.assertEqual(len(result), 255)
        self.assertTrue(result.endswith(".html"))

    def test_sanitize_filename_long_with_html_extension(self):
        """Test long filename that already has .html extension."""
        long_with_ext = "d" * 300 + ".html"
        result = md_converter.sanitize_filename(long_with_ext)
        self.assertEqual(len(result), 255)
        self.assertTrue(result.endswith(".html"))
        self.assertEqual(result, "d" * 250 + ".html")

    def test_sanitize_filename_only_special_chars(self):
        """Test filename with only strippable characters."""
        self.assertEqual(md_converter.sanitize_filename(".."), "document.html")
        self.assertEqual(md_converter.sanitize_filename("___"), "document.html")
        self.assertEqual(md_converter.sanitize_filename("-.-"), "document.html")
        self.assertEqual(md_converter.sanitize_filename("..."), "document.html")

    def test_sanitize_filename_whitespace(self):
        """Test filename with whitespace characters."""
        self.assertEqual(md_converter.sanitize_filename("test file"), "test_file.html")
        self.assertEqual(md_converter.sanitize_filename("test  file"), "test_file.html")
        self.assertEqual(md_converter.sanitize_filename("  test  "), "test.html")


class TestGenerateJavascript(unittest.TestCase):
    """Test JavaScript generation."""

    def test_generate_javascript_basic(self):
        """Test basic JavaScript generation with mocked vendor libs."""
        vendor_libs = {
            "marked": "// marked.js placeholder",
            "purify": "// purify.js placeholder"
        }
        js = md_converter.generate_javascript(
            vendor_libs=vendor_libs,
            toc_mode="none",
            toc_levels="h2",
            collapsible_mode="none",
            start_collapsed=False,
            back_to_top=False,
            search_enabled=False,
            highlight_enabled=False,
            katex_enabled=False,
            line_numbers=False
        )
        # Should contain script tags
        self.assertIn("<script>", js)
        # Should contain the constants
        self.assertIn("TOC_MODE", js)
        self.assertIn("SEARCH_ENABLED", js)

    def test_generate_javascript_escape_sequences(self):
        """Test that JavaScript contains properly escaped regex patterns."""
        vendor_libs = {
            "marked": "// marked.js",
            "purify": "// purify.js"
        }
        js = md_converter.generate_javascript(
            vendor_libs=vendor_libs,
            toc_mode="none",
            toc_levels="h2",
            collapsible_mode="none",
            start_collapsed=False,
            back_to_top=False,
            search_enabled=False,
            highlight_enabled=False,
            katex_enabled=False,
            line_numbers=False
        )
        # Should contain properly escaped dollar signs in regex
        self.assertIn(r"/\$\$", js)  # Display math regex
        # Should contain properly escaped whitespace pattern
        self.assertIn(r"\s", js)  # slugify function


class TestBuildHtml(unittest.TestCase):
    """Test HTML building."""

    def test_build_html_basic(self):
        """Test basic HTML generation."""
        vendor_libs = {
            "marked": "// marked.js placeholder",
            "purify": "// purify.js placeholder"
        }
        html = md_converter.build_html(
            md_text="# Test\n\nHello world",
            meta={"title": "Test Document"},
            vendor_libs=vendor_libs,
            toc_mode="none",
            toc_levels="h2",
            back_to_top=False,
            search_enabled=False,
            collapsible_mode="none",
            start_collapsed=False,
            theme_preset="default",
            highlight_enabled=False,
            highlight_theme="github-light",
            katex_enabled=False,
            line_numbers=False,
            base_font_size="100%",
            content_width="900px"
        )
        # Should be valid HTML structure
        self.assertIn("<!doctype html>", html)
        self.assertIn("<html", html)
        self.assertIn("</html>", html)
        self.assertIn("<title>Test Document</title>", html)
        # Should contain the markdown in script tag
        self.assertIn("# Test", html)
        self.assertIn("Hello world", html)

    def test_build_html_escapes_script_in_markdown(self):
        """Test that script tags in markdown are escaped."""
        vendor_libs = {
            "marked": "// marked.js",
            "purify": "// purify.js"
        }
        html = md_converter.build_html(
            md_text="Test </script> content",
            meta={"title": "Test"},
            vendor_libs=vendor_libs,
            toc_mode="none",
            toc_levels="h2",
            back_to_top=False,
            search_enabled=False,
            collapsible_mode="none",
            start_collapsed=False
        )
        # Should not contain unescaped </script> in the markdown section
        # The md-source script tag should not be prematurely closed
        self.assertIn("md-source", html)
        # Count script tags - should be balanced
        open_tags = html.count("<script")
        close_tags = html.count("</script>")
        self.assertEqual(open_tags, close_tags)


class TestHighlightThemeCss(unittest.TestCase):
    """Test syntax highlighting theme CSS."""

    def test_get_highlight_theme_css_valid(self):
        """Test valid highlight themes return CSS."""
        themes = ["github-light", "github-dark", "monokai", "atom-one-dark"]
        for theme in themes:
            css = md_converter.get_highlight_theme_css(theme)
            self.assertIsInstance(css, str)
            self.assertIn(".hljs", css)

    def test_get_highlight_theme_css_invalid(self):
        """Test invalid theme falls back to github-light."""
        result = md_converter.get_highlight_theme_css("nonexistent")
        default = md_converter.get_highlight_theme_css("github-light")
        self.assertEqual(result, default)


class TestGenerateTocContainers(unittest.TestCase):
    """Test ToC container generation."""

    def test_generate_toc_containers_top(self):
        """Test top ToC container generation."""
        top, sidebar = md_converter.generate_toc_containers("top")
        self.assertIn('id="toc"', top)
        self.assertIn("Table of Contents", top)
        self.assertEqual(sidebar, "")

    def test_generate_toc_containers_sidebar(self):
        """Test sidebar ToC container generation."""
        top, sidebar = md_converter.generate_toc_containers("sidebar")
        self.assertEqual(top, "")
        self.assertIn('id="toc-sidebar"', sidebar)
        self.assertIn("tocSidebarClose", sidebar)

    def test_generate_toc_containers_none(self):
        """Test no ToC container generation."""
        top, sidebar = md_converter.generate_toc_containers("none")
        self.assertEqual(top, "")
        self.assertEqual(sidebar, "")


class TestSanitizeCssSize(unittest.TestCase):
    """Test CSS size sanitization."""

    def test_sanitize_css_size_valid(self):
        """Test valid CSS sizes are returned unchanged."""
        self.assertEqual(md_converter.sanitize_css_size("100%", "50%"), "100%")
        self.assertEqual(md_converter.sanitize_css_size("16px", "12px"), "16px")

    def test_sanitize_css_size_invalid_uses_default(self):
        """Test invalid CSS sizes return the default."""
        self.assertEqual(md_converter.sanitize_css_size("invalid", "100%"), "100%")
        self.assertEqual(md_converter.sanitize_css_size("", "50px"), "50px")


class TestSymlinkProtection(unittest.TestCase):
    """Test symlink protection in safe_read_file."""

    def test_symlink_outside_base_blocked(self):
        """Test that symlinks pointing outside base directory are blocked."""
        import tempfile
        import os

        # Create temp directory structure
        base_dir = tempfile.mkdtemp()
        secret_file = tempfile.NamedTemporaryFile(mode='w', delete=False, dir='/tmp')
        secret_file.write('SECRET_DATA')
        secret_file.close()

        # Create symlink inside base_dir pointing to secret file
        symlink_path = os.path.join(base_dir, 'symlink.md')
        os.symlink(secret_file.name, symlink_path)

        try:
            # This should raise ValueError because symlink resolves outside base
            with self.assertRaises(ValueError) as context:
                md_converter.safe_read_file(base_dir, 'symlink.md')
            self.assertIn("Security violation", str(context.exception))
        finally:
            os.unlink(symlink_path)
            os.unlink(secret_file.name)
            os.rmdir(base_dir)

    def test_regular_file_inside_base_allowed(self):
        """Test that regular files inside base directory are allowed."""
        import tempfile
        import os

        base_dir = tempfile.mkdtemp()
        test_file = os.path.join(base_dir, 'test.md')
        with open(test_file, 'w') as f:
            f.write('test content')

        try:
            content = md_converter.safe_read_file(base_dir, 'test.md')
            self.assertEqual(content, 'test content')
        finally:
            os.unlink(test_file)
            os.rmdir(base_dir)


class TestScriptTagEscapeBypass(unittest.TestCase):
    """Test script tag escape with whitespace variants."""

    def test_escape_script_with_space(self):
        """Test escaping </script > with trailing space."""
        result = md_converter.escape_for_script_tag("</script >")
        self.assertNotIn("</script", result.lower())

    def test_escape_script_with_tab(self):
        """Test escaping </script\t> with tab."""
        result = md_converter.escape_for_script_tag("</script\t>")
        self.assertNotIn("</script", result.lower())

    def test_escape_script_with_newline(self):
        """Test escaping </script\n> with newline."""
        result = md_converter.escape_for_script_tag("</script\n>")
        self.assertNotIn("</script", result.lower())

    def test_escape_html_comment(self):
        """Test escaping HTML comments which could break script context."""
        result = md_converter.escape_for_script_tag("<!--comment-->")
        self.assertNotIn("<!--", result)

    def test_escape_multiple_variants(self):
        """Test escaping multiple script tag variants in one string."""
        input_str = "a</script>b</SCRIPT >c</script\t>d"
        result = md_converter.escape_for_script_tag(input_str)
        self.assertNotIn("</script>", result.lower())
        self.assertNotIn("</script ", result.lower())


class TestSanitizeFilenameCaseSensitivity(unittest.TestCase):
    """Test case-insensitive handling of .html extension."""

    def test_uppercase_html_extension(self):
        """Test that .HTML extension is recognized."""
        self.assertEqual(md_converter.sanitize_filename("test.HTML"), "test.html")

    def test_mixed_case_html_extension(self):
        """Test that .Html extension is recognized."""
        self.assertEqual(md_converter.sanitize_filename("test.Html"), "test.html")

    def test_lowercase_html_extension(self):
        """Test that .html extension is recognized."""
        self.assertEqual(md_converter.sanitize_filename("test.html"), "test.html")

    def test_no_double_extension(self):
        """Test that we don't get double .html extensions."""
        result = md_converter.sanitize_filename("document.HTML")
        self.assertEqual(result.count('.html'), 1)


class TestDeepNestingParsing(unittest.TestCase):
    """Test parsing of deeply nested SUMMARY.md files."""

    def test_more_than_10_levels(self):
        """Test parsing with more than 10 nesting levels doesn't crash."""
        import tempfile
        import os

        # Create deeply nested summary
        lines = ["# Summary\n"]
        for i in range(15):  # 15 levels deep
            indent = "  " * i
            lines.append(f"{indent}- [Level {i}](l{i}.md)\n")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.writelines(lines)
            temp_path = f.name

        try:
            # This should not raise IndexError
            chapters = md_converter.parse_summary_md(temp_path)
            self.assertEqual(len(chapters), 15)
            # Verify deepest chapter has correct level
            self.assertEqual(chapters[-1].level, 14)
        finally:
            os.unlink(temp_path)

    def test_chapter_numbering_deep_nesting(self):
        """Test chapter numbering works correctly with deep nesting."""
        import tempfile
        import os

        summary = """# Summary

- [Ch 1](c1.md)
  - [Ch 1.1](c11.md)
    - [Ch 1.1.1](c111.md)
- [Ch 2](c2.md)
  - [Ch 2.1](c21.md)
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(summary)
            temp_path = f.name

        try:
            chapters = md_converter.parse_summary_md(temp_path)
            numbers = [c.number for c in chapters if c.number]
            self.assertEqual(numbers, ['1', '1.1', '1.1.1', '2', '2.1'])
        finally:
            os.unlink(temp_path)


class TestPathWithParentheses(unittest.TestCase):
    """Test parsing paths that contain parentheses."""

    def test_path_with_parentheses(self):
        """Test that paths with parentheses are parsed correctly."""
        import tempfile
        import os

        summary = """# Summary

- [Chapter](path(with)parens.md)
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(summary)
            temp_path = f.name

        try:
            chapters = md_converter.parse_summary_md(temp_path)
            chapter = [c for c in chapters if c.path][0]
            self.assertEqual(chapter.path, "path(with)parens.md")
        finally:
            os.unlink(temp_path)

    def test_path_with_nested_parentheses(self):
        """Test that paths with nested parentheses are parsed correctly."""
        import tempfile
        import os

        summary = """# Summary

- [Chapter](path(with(nested))parens.md)
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(summary)
            temp_path = f.name

        try:
            chapters = md_converter.parse_summary_md(temp_path)
            chapter = [c for c in chapters if c.path][0]
            self.assertEqual(chapter.path, "path(with(nested))parens.md")
        finally:
            os.unlink(temp_path)

    def test_empty_path_draft(self):
        """Test that empty paths are recognized as drafts."""
        import tempfile
        import os

        summary = """# Summary

- [Draft Chapter]()
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(summary)
            temp_path = f.name

        try:
            chapters = md_converter.parse_summary_md(temp_path)
            chapter = [c for c in chapters if not c.is_separator and not c.is_part_title][0]
            self.assertTrue(chapter.is_draft)
            self.assertIsNone(chapter.path)
        finally:
            os.unlink(temp_path)


class TestCombineChaptersHeadingLevel(unittest.TestCase):
    """Test that combine_chapters caps heading levels at H6."""

    def test_deep_chapter_capped_at_h6(self):
        """Test that deeply nested chapters don't exceed H6."""
        # Create chapters with deep nesting
        chapters = [
            md_converter.Chapter("L0", path="l0.md", level=0),
            md_converter.Chapter("L4", path="l4.md", level=4),  # Would be H6
            md_converter.Chapter("L5", path="l5.md", level=5),  # Would be H7 without cap
            md_converter.Chapter("L10", path="l10.md", level=10),  # Would be H12 without cap
        ]

        # Mock the file reading
        with patch.object(md_converter, 'read_markdown_file', return_value="Content here"):
            combined, metadata = md_converter.combine_chapters(chapters, "/fake/path")

        # Check that heading levels are capped
        self.assertIn("## L0", combined)  # Level 0 -> H2
        self.assertIn("###### L4", combined)  # Level 4 -> H6
        self.assertIn("###### L5", combined)  # Level 5 -> H6 (capped)
        self.assertIn("###### L10", combined)  # Level 10 -> H6 (capped)

        # Ensure no H7 or higher
        self.assertNotIn("####### ", combined)


class TestH1RemovalWithLeadingBlanks(unittest.TestCase):
    """Test that H1 removal works when markdown has leading blank lines."""

    def test_h1_removed_after_blank_lines(self):
        """Test H1 is removed even if preceded by blank lines."""
        chapter = md_converter.Chapter("Test Chapter", path="test.md", level=0)

        markdown_with_leading_blanks = "\n\n\n# Title to Remove\n\nActual content here."

        with patch.object(md_converter, 'read_markdown_file', return_value=markdown_with_leading_blanks):
            combined, metadata = md_converter.combine_chapters([chapter], "/fake/path")

        # The original H1 should be removed
        self.assertNotIn("# Title to Remove", combined)
        # But the chapter heading should be there
        self.assertIn("## Test Chapter", combined)
        # And the content should be preserved
        self.assertIn("Actual content here", combined)

    def test_h1_not_removed_if_not_first(self):
        """Test that H1 in the middle of content is not removed."""
        chapter = md_converter.Chapter("Test Chapter", path="test.md", level=0)

        markdown_with_h1_later = "Some intro text.\n\n# Not First H1\n\nMore content."

        with patch.object(md_converter, 'read_markdown_file', return_value=markdown_with_h1_later):
            combined, metadata = md_converter.combine_chapters([chapter], "/fake/path")

        # This H1 should NOT be removed because it's not the first non-blank line
        self.assertIn("# Not First H1", combined)


class TestValidateProjectPathSymlink(unittest.TestCase):
    """Test that validate_project_path resolves symlinks."""

    def test_symlink_to_sensitive_dir_blocked(self):
        """Test that symlinks pointing to sensitive directories are blocked."""
        import tempfile
        import os

        # Create a symlink pointing to /etc
        temp_dir = tempfile.mkdtemp()
        symlink_path = os.path.join(temp_dir, 'etc_link')

        try:
            os.symlink('/etc', symlink_path)
            is_valid, error = md_converter.validate_project_path(symlink_path)
            self.assertFalse(is_valid)
            self.assertIn("/etc", error)
        finally:
            os.unlink(symlink_path)
            os.rmdir(temp_dir)


class TestTabIndentation(unittest.TestCase):
    """Test tab indentation handling in parse_summary_md."""

    def test_tab_indentation(self):
        """Test that tab characters are handled correctly."""
        import tempfile
        import os

        # Use tabs for indentation (1 tab = 4 spaces = 2 levels)
        summary = """# Summary

- [Level 0](l0.md)
\t- [Level 2](l2.md)
\t\t- [Level 4](l4.md)
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(summary)
            temp_path = f.name

        try:
            chapters = md_converter.parse_summary_md(temp_path)
            levels = [c.level for c in chapters if c.path]
            # 1 tab = 4 spaces = 2 levels
            self.assertEqual(levels, [0, 2, 4])
        finally:
            os.unlink(temp_path)

    def test_mixed_tabs_and_spaces(self):
        """Test mixed tab and space indentation."""
        import tempfile
        import os

        # Mix tabs and spaces
        summary = """# Summary

- [Level 0](l0.md)
  - [Level 1](l1.md)
\t- [Level 2](l2.md)
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            f.write(summary)
            temp_path = f.name

        try:
            chapters = md_converter.parse_summary_md(temp_path)
            levels = [c.level for c in chapters if c.path]
            self.assertEqual(levels, [0, 1, 2])
        finally:
            os.unlink(temp_path)


class TestUnicodeEscaping(unittest.TestCase):
    """Test Unicode line separator escaping."""

    def test_escape_line_separator(self):
        """Test U+2028 LINE SEPARATOR is escaped."""
        result = md_converter.escape_js_string("test\u2028line")
        self.assertIn("\\u2028", result)
        self.assertNotIn("\u2028", result)

    def test_escape_paragraph_separator(self):
        """Test U+2029 PARAGRAPH SEPARATOR is escaped."""
        result = md_converter.escape_js_string("test\u2029para")
        self.assertIn("\\u2029", result)
        self.assertNotIn("\u2029", result)

    def test_escape_combined(self):
        """Test both separators together."""
        result = md_converter.escape_js_string("a\u2028b\u2029c")
        self.assertIn("\\u2028", result)
        self.assertIn("\\u2029", result)


class TestByteCountTruncation(unittest.TestCase):
    """Test filename truncation by byte count for Unicode safety."""

    def test_ascii_truncation(self):
        """Test ASCII filename truncation works."""
        long_name = "a" * 300
        result = md_converter.sanitize_filename(long_name)
        # Should be 250 bytes + 5 bytes (.html) = 255 bytes max
        self.assertLessEqual(len(result.encode('utf-8')), 255)
        self.assertTrue(result.endswith('.html'))

    def test_unicode_truncation(self):
        """Test Unicode filename truncation respects byte limits."""
        # Each emoji is 4 bytes in UTF-8
        emoji_name = "📄" * 100  # 400 bytes of emoji
        result = md_converter.sanitize_filename(emoji_name)
        # Should be truncated to fit within 255 bytes
        self.assertLessEqual(len(result.encode('utf-8')), 255)
        self.assertTrue(result.endswith('.html'))

    def test_cjk_truncation(self):
        """Test CJK character truncation respects byte limits."""
        # Each CJK character is 3 bytes in UTF-8
        cjk_name = "文" * 100  # 300 bytes of CJK
        result = md_converter.sanitize_filename(cjk_name)
        self.assertLessEqual(len(result.encode('utf-8')), 255)
        self.assertTrue(result.endswith('.html'))


class TestFileSizeLimits(unittest.TestCase):
    """Test file size limit constants are defined."""

    def test_max_markdown_size_defined(self):
        """Test MAX_MARKDOWN_SIZE constant exists."""
        self.assertTrue(hasattr(md_converter, 'MAX_MARKDOWN_SIZE'))
        self.assertGreater(md_converter.MAX_MARKDOWN_SIZE, 0)

    def test_max_vendor_js_size_defined(self):
        """Test MAX_VENDOR_JS_SIZE constant exists."""
        self.assertTrue(hasattr(md_converter, 'MAX_VENDOR_JS_SIZE'))
        self.assertGreater(md_converter.MAX_VENDOR_JS_SIZE, 0)


if __name__ == "__main__":
    unittest.main()
