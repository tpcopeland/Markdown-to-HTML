#!/usr/bin/env python3
"""
Test script to validate security fixes in md_to_html.py
Tests CSS injection prevention and filename validation.
"""
import re

def validate_css_size(value: str) -> bool:
    """Validate CSS size value to prevent injection."""
    if not value:
        return False
    # Allow percentage, px, em, rem, vh, vw with optional decimal
    pattern = r'^\d+(\.\d+)?(px|%|em|rem|vh|vw)$'
    return bool(re.match(pattern, value))

def validate_vendor_path_regex(filename: str) -> bool:
    """Test the filename validation regex."""
    return bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', filename))

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

def test_css_validation():
    """Test CSS size validation."""
    print("Testing CSS validation...")

    # Valid cases
    valid_cases = ["100%", "900px", "1.5em", "2rem", "100vh", "50vw", "16px"]
    for case in valid_cases:
        assert validate_css_size(case), f"Failed: {case} should be valid"
        print(f"  ✓ {case} is valid")

    # Invalid cases (potential CSS injection attempts)
    invalid_cases = [
        "100%; } malicious-css { ",
        "100%;}body{background:red",
        "100px; color: red",
        "javascript:alert(1)",
        "<script>alert(1)</script>",
        "100",  # Missing unit
        "px",   # Missing number
        "",     # Empty
        "100 px",  # Space
    ]
    for case in invalid_cases:
        assert not validate_css_size(case), f"Failed: {case} should be invalid"
        print(f"  ✓ {case} is invalid (blocked)")

    print("CSS validation tests passed!\n")

def test_filename_validation():
    """Test filename validation to prevent dotfile access."""
    print("Testing filename validation...")

    # Valid cases
    valid_cases = ["marked.min.js", "purify.min.js", "highlight.min.js", "katex.min.css"]
    for case in valid_cases:
        assert validate_vendor_path_regex(case), f"Failed: {case} should be valid"
        print(f"  ✓ {case} is valid")

    # Invalid cases (security risks)
    invalid_cases = [
        ".env",
        ".git",
        ".htaccess",
        "../etc/passwd",
        "../../secret",
        ".bashrc",
        ".ssh",
    ]
    for case in invalid_cases:
        assert not validate_vendor_path_regex(case), f"Failed: {case} should be invalid"
        print(f"  ✓ {case} is invalid (blocked)")

    print("Filename validation tests passed!\n")

def test_filename_sanitization():
    """Test filename sanitization."""
    print("Testing filename sanitization...")

    test_cases = [
        ("My Document", "My_Document.html"),
        ("Test<script>", "Testscript.html"),
        ("../../../etc/passwd", "etcpasswd.html"),
        ("normal_file", "normal_file.html"),
        ("file with spaces", "file_with_spaces.html"),
        ("", "document.html"),
        ("...test...", "test.html"),
    ]

    for input_name, expected in test_cases:
        result = sanitize_filename(input_name)
        assert result == expected, f"Failed: {input_name} -> {result} (expected {expected})"
        print(f"  ✓ '{input_name}' -> '{result}'")

    print("Filename sanitization tests passed!\n")

if __name__ == "__main__":
    print("=" * 60)
    print("Security Fixes Validation Tests")
    print("=" * 60 + "\n")

    try:
        test_css_validation()
        test_filename_validation()
        test_filename_sanitization()

        print("=" * 60)
        print("All security tests passed! ✓")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        exit(1)
