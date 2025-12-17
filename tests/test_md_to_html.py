"""
Unit tests for md_to_html.py

Tests security features, input validation, and core functionality.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Create comprehensive streamlit mock before importing md_to_html
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

import md_to_html


class TestEscapeHtml(unittest.TestCase):
    """Test HTML escaping function."""

    def test_escape_html_basic(self):
        """Test basic HTML character escaping."""
        self.assertEqual(md_to_html.escape_html("<script>"), "&lt;script&gt;")
        self.assertEqual(md_to_html.escape_html("a & b"), "a &amp; b")
        self.assertEqual(md_to_html.escape_html('"test"'), "&quot;test&quot;")
        self.assertEqual(md_to_html.escape_html("'test'"), "&#x27;test&#x27;")

    def test_escape_html_empty(self):
        """Test empty string handling."""
        self.assertEqual(md_to_html.escape_html(""), "")
        self.assertEqual(md_to_html.escape_html(None), "")

    def test_escape_html_combined(self):
        """Test combined special characters."""
        input_str = '<a href="test">click & go</a>'
        expected = "&lt;a href=&quot;test&quot;&gt;click &amp; go&lt;/a&gt;"
        self.assertEqual(md_to_html.escape_html(input_str), expected)


class TestEscapeJsString(unittest.TestCase):
    """Test JavaScript string escaping function."""

    def test_escape_js_string_basic(self):
        """Test basic JS escaping."""
        self.assertEqual(md_to_html.escape_js_string("test's"), "test\\'s")
        self.assertEqual(md_to_html.escape_js_string('test"s'), 'test\\"s')
        self.assertEqual(md_to_html.escape_js_string("line\nbreak"), "line\\nbreak")

    def test_escape_js_string_script_tag(self):
        """Test script tag escaping."""
        self.assertEqual(md_to_html.escape_js_string("</script>"), "<\\/script>")

    def test_escape_js_string_empty(self):
        """Test empty string handling."""
        self.assertEqual(md_to_html.escape_js_string(""), "")
        self.assertEqual(md_to_html.escape_js_string(None), "")


class TestEscapeForScriptTag(unittest.TestCase):
    """Test script tag content escaping."""

    def test_escape_script_tag_closing(self):
        """Test closing script tag escaping."""
        self.assertEqual(md_to_html.escape_for_script_tag("</script>"), "<\\/script>")
        # Case-insensitive replacement - all variants become lowercase escaped
        # This is safe because the browser won't close the tag regardless of case
        result_upper = md_to_html.escape_for_script_tag("</SCRIPT>")
        self.assertIn("<\\/", result_upper)
        result_mixed = md_to_html.escape_for_script_tag("</Script>")
        self.assertIn("<\\/", result_mixed)

    def test_escape_script_tag_empty(self):
        """Test empty string handling."""
        self.assertEqual(md_to_html.escape_for_script_tag(""), "")
        self.assertEqual(md_to_html.escape_for_script_tag(None), "")


class TestSanitizeForHtmlComment(unittest.TestCase):
    """Test HTML comment sanitization."""

    def test_sanitize_double_dash(self):
        """Test double dash escaping."""
        self.assertEqual(md_to_html.sanitize_for_html_comment("--"), "&#45;&#45;")
        self.assertEqual(md_to_html.sanitize_for_html_comment("test--value"), "test&#45;&#45;value")

    def test_sanitize_comment_breakout(self):
        """Test comment breakout prevention."""
        # This would normally break out of a comment
        result = md_to_html.sanitize_for_html_comment("-->")
        self.assertNotIn("-->", result)

    def test_sanitize_empty(self):
        """Test empty string handling."""
        self.assertEqual(md_to_html.sanitize_for_html_comment(""), "")
        self.assertEqual(md_to_html.sanitize_for_html_comment(None), "")


class TestValidateCssSize(unittest.TestCase):
    """Test CSS size validation."""

    def test_validate_css_size_valid(self):
        """Test valid CSS sizes."""
        self.assertTrue(md_to_html.validate_css_size("100%"))
        self.assertTrue(md_to_html.validate_css_size("16px"))
        self.assertTrue(md_to_html.validate_css_size("1.5em"))
        self.assertTrue(md_to_html.validate_css_size("2rem"))
        self.assertTrue(md_to_html.validate_css_size("100vh"))
        self.assertTrue(md_to_html.validate_css_size("50vw"))

    def test_validate_css_size_invalid(self):
        """Test invalid CSS sizes."""
        self.assertFalse(md_to_html.validate_css_size(""))
        self.assertFalse(md_to_html.validate_css_size("abc"))
        self.assertFalse(md_to_html.validate_css_size("100"))
        self.assertFalse(md_to_html.validate_css_size("100pt"))
        self.assertFalse(md_to_html.validate_css_size("url(evil.css)"))
        self.assertFalse(md_to_html.validate_css_size("100%; injection"))

    def test_validate_css_size_injection(self):
        """Test CSS injection attempts."""
        self.assertFalse(md_to_html.validate_css_size("100%}body{color:red"))
        self.assertFalse(md_to_html.validate_css_size("expression(alert())"))


class TestSanitizeFilename(unittest.TestCase):
    """Test filename sanitization."""

    def test_sanitize_filename_basic(self):
        """Test basic filename sanitization."""
        self.assertEqual(md_to_html.sanitize_filename("test"), "test.html")
        self.assertEqual(md_to_html.sanitize_filename("test.html"), "test.html")

    def test_sanitize_filename_special_chars(self):
        """Test special character removal."""
        self.assertEqual(md_to_html.sanitize_filename("test<>file"), "testfile.html")
        self.assertEqual(md_to_html.sanitize_filename("test/file"), "testfile.html")

    def test_sanitize_filename_empty(self):
        """Test empty filename handling."""
        self.assertEqual(md_to_html.sanitize_filename(""), "document.html")
        self.assertEqual(md_to_html.sanitize_filename(None), "document.html")

    def test_sanitize_filename_path_traversal(self):
        """Test path traversal prevention."""
        result = md_to_html.sanitize_filename("../../../etc/passwd")
        self.assertNotIn("..", result)
        self.assertNotIn("/", result)


class TestValidateDate(unittest.TestCase):
    """Test date validation."""

    def test_validate_date_valid(self):
        """Test valid ISO dates."""
        self.assertTrue(md_to_html.validate_date("2024-01-15"))
        self.assertTrue(md_to_html.validate_date(""))  # Empty is valid

    def test_validate_date_invalid(self):
        """Test invalid dates."""
        self.assertFalse(md_to_html.validate_date("2024/01/15"))
        self.assertFalse(md_to_html.validate_date("01-15-2024"))
        self.assertFalse(md_to_html.validate_date("not-a-date"))


class TestValidateVendorPath(unittest.TestCase):
    """Test vendor path validation."""

    def setUp(self):
        """Set up test fixtures."""
        self.vendor_dir = md_to_html.VENDOR_DIR

    def test_validate_vendor_path_valid(self):
        """Test valid vendor filenames."""
        # Should not raise
        result = md_to_html.validate_vendor_path(self.vendor_dir, "marked.umd.min.js")
        self.assertTrue(result.endswith("marked.umd.min.js"))

    def test_validate_vendor_path_traversal(self):
        """Test path traversal prevention."""
        # These should trigger st.error and st.stop (mocked)
        with self.assertRaises(SystemExit):
            md_to_html.validate_vendor_path(self.vendor_dir, "../secret.txt")

    def test_validate_vendor_path_dotfile(self):
        """Test dotfile prevention."""
        with self.assertRaises(SystemExit):
            md_to_html.validate_vendor_path(self.vendor_dir, ".hidden")


class TestValidateProjectPath(unittest.TestCase):
    """Test project path validation."""

    def test_validate_project_path_valid(self):
        """Test valid project paths."""
        is_valid, error = md_to_html.validate_project_path("/home/user/project")
        self.assertTrue(is_valid)
        self.assertEqual(error, "")

    def test_validate_project_path_traversal(self):
        """Test path traversal prevention."""
        is_valid, error = md_to_html.validate_project_path("../../../etc")
        self.assertFalse(is_valid)
        self.assertIn("traversal", error.lower())

    def test_validate_project_path_sensitive(self):
        """Test sensitive directory blocking."""
        sensitive_dirs = ["/etc", "/var", "/root", "/sys", "/proc", "/dev", "/boot"]
        for path in sensitive_dirs:
            is_valid, error = md_to_html.validate_project_path(path)
            self.assertFalse(is_valid, f"Should block {path}")

    def test_validate_project_path_empty(self):
        """Test empty path handling."""
        is_valid, error = md_to_html.validate_project_path("")
        self.assertFalse(is_valid)


class TestSafeReadFile(unittest.TestCase):
    """Test safe file reading."""

    def test_safe_read_file_traversal(self):
        """Test path traversal prevention."""
        with self.assertRaises(ValueError) as context:
            md_to_html.safe_read_file("/tmp/test", "../../../etc/passwd")
        self.assertIn("Security violation", str(context.exception))


class TestGetThemeCss(unittest.TestCase):
    """Test theme CSS generation."""

    def test_get_theme_css_valid_themes(self):
        """Test valid theme names."""
        themes = ["default", "github", "academic", "minimal", "dark"]
        for theme in themes:
            result = md_to_html.get_theme_css(theme)
            self.assertIsInstance(result, list)
            self.assertGreater(len(result), 0)

    def test_get_theme_css_invalid(self):
        """Test invalid theme falls back to default."""
        result = md_to_html.get_theme_css("nonexistent")
        default = md_to_html.get_theme_css("default")
        self.assertEqual(result, default)


class TestGenerateCss(unittest.TestCase):
    """Test CSS generation."""

    def test_generate_css_valid_sizes(self):
        """Test CSS generation with valid sizes."""
        css = md_to_html.generate_css(
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
        css = md_to_html.generate_css(
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
        toolbar = md_to_html.generate_toolbar(
            title='<script>alert("xss")</script>',
            toc_mode="none",
            search_enabled=False,
            theme_preset="default"
        )
        self.assertNotIn("<script>", toolbar)
        self.assertIn("&lt;script&gt;", toolbar)

    def test_generate_toolbar_dark_theme_no_toggle(self):
        """Test dark theme preset doesn't show theme toggle."""
        toolbar = md_to_html.generate_toolbar(
            title="Test",
            toc_mode="none",
            search_enabled=False,
            theme_preset="dark"
        )
        self.assertNotIn("themeToggle", toolbar)

    def test_generate_toolbar_light_theme_has_toggle(self):
        """Test non-dark theme shows theme toggle."""
        toolbar = md_to_html.generate_toolbar(
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
        chapter = md_to_html.Chapter(
            title="Test Chapter",
            path="test.md",
            level=0,
            is_draft=False
        )
        self.assertEqual(chapter.title, "Test Chapter")
        self.assertEqual(chapter.path, "test.md")
        self.assertEqual(chapter.level, 0)
        self.assertFalse(chapter.is_draft)


if __name__ == "__main__":
    unittest.main()
