"""
Unit tests for md_converter.py

Tests DOCX conversion utilities.
"""
import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import md_converter


class TestPreprocessMarkdownForDocx(unittest.TestCase):
    """Test markdown preprocessing for DOCX conversion."""

    def test_insert_blank_line_before_list(self):
        """Test blank line is inserted before bullet list."""
        content = "Some text\n- Item 1\n- Item 2"
        result = md_converter._preprocess_markdown_for_docx(content)
        self.assertIn("\n\n- Item 1", result)

    def test_no_extra_blank_for_existing(self):
        """Test no extra blank line if already present."""
        content = "Some text\n\n- Item 1\n- Item 2"
        result = md_converter._preprocess_markdown_for_docx(content)
        # Should still have exactly one blank line
        self.assertEqual(result.count("\n\n- Item 1"), 1)

    def test_remove_blank_between_bullets(self):
        """Test blank lines between bullets are removed."""
        content = "Some text\n\n- Item 1\n\n- Item 2\n\n- Item 3"
        result = md_converter._preprocess_markdown_for_docx(content)
        # Bullets should be consecutive
        self.assertIn("- Item 1\n- Item 2\n- Item 3", result)

    def test_indented_bullets(self):
        """Test indented bullets are recognized."""
        content = "Text\n  - Indented item"
        result = md_converter._preprocess_markdown_for_docx(content)
        self.assertIn("\n\n  - Indented item", result)


class TestSanitizeFilenameForFormat(unittest.TestCase):
    """Test filename sanitization for different formats."""

    def test_basic_docx(self):
        """Test basic DOCX filename."""
        result = md_converter.sanitize_filename_for_format("test", ".docx")
        self.assertEqual(result, "test.docx")

    def test_removes_existing_extension(self):
        """Test existing extension is removed."""
        result = md_converter.sanitize_filename_for_format("test.md", ".docx")
        self.assertEqual(result, "test.docx")

    def test_empty_name(self):
        """Test empty name gets default."""
        result = md_converter.sanitize_filename_for_format("", ".docx")
        self.assertEqual(result, "document.docx")

    def test_special_chars_removed(self):
        """Test special characters are removed."""
        result = md_converter.sanitize_filename_for_format("test<>file", ".docx")
        self.assertEqual(result, "testfile.docx")

    def test_byte_limit_respected(self):
        """Test filename respects byte limits."""
        # Very long name with Unicode
        long_name = "文" * 100  # 300 bytes in UTF-8
        result = md_converter.sanitize_filename_for_format(long_name, ".docx")
        # Result should be at most 255 bytes
        self.assertLessEqual(len(result.encode('utf-8')), 255)
        self.assertTrue(result.endswith('.docx'))


class TestCheckDocxDependencies(unittest.TestCase):
    """Test dependency checking."""

    def test_returns_tuple(self):
        """Test function returns a tuple."""
        result = md_converter.check_docx_dependencies()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_first_element_is_bool(self):
        """Test first element is boolean."""
        available, error = md_converter.check_docx_dependencies()
        self.assertIsInstance(available, bool)

    def test_second_element_is_string(self):
        """Test second element is string."""
        available, error = md_converter.check_docx_dependencies()
        self.assertIsInstance(error, str)


class TestPostprocessDocx(unittest.TestCase):
    """Test DOCX post-processing."""

    def test_valid_docx_structure(self):
        """Test post-processing preserves valid DOCX structure."""
        import zipfile
        import io

        # Create a minimal valid DOCX structure
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            # Add minimal required files
            zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types></Types>')
            zf.writestr('word/document.xml', '<?xml version="1.0"?><document></document>')
            zf.writestr('word/styles.xml', '<?xml version="1.0"?><styles></styles>')

        buffer.seek(0)
        docx_bytes = buffer.read()

        # Post-process should not crash
        result = md_converter._postprocess_docx(docx_bytes)

        # Result should be valid ZIP
        result_buffer = io.BytesIO(result)
        with zipfile.ZipFile(result_buffer, 'r') as zf:
            self.assertIn('word/document.xml', zf.namelist())


if __name__ == "__main__":
    unittest.main()
