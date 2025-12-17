# Test Document

This is a test document for validating the Markdown to HTML converter.

## Code Blocks

### Python Example

```python
def hello_world():
    """Print a greeting."""
    print("Hello, World!")
    return True

if __name__ == "__main__":
    hello_world()
```

### Output Example

```output
Hello, World!
Process completed successfully.
```

## Math Expressions

### Inline Math

The quadratic formula is $x = \frac{-b \pm \sqrt{b^2-4ac}}{2a}$.

Currency values like $100 or $50 should not be treated as math.

### Display Math

The Pythagorean theorem:

$$a^2 + b^2 = c^2$$

Einstein's famous equation:

$$E = mc^2$$

## Tables

| Feature | Status | Notes |
|---------|--------|-------|
| ToC | Working | Multiple modes |
| Search | Working | Highlights matches |
| Themes | Working | 5 presets |
| Math | Working | KaTeX rendering |

## Security Test Content

### XSS Prevention Tests

This content includes potential XSS vectors that should be sanitized:

- Script tag: <script>alert('xss')</script>
- Event handler: <img onerror="alert('xss')">
- Protocol handler: <a href="javascript:alert('xss')">click me</a>

### Path Traversal Test

References to paths like `../../../etc/passwd` should be handled safely.

## Special Characters

- Ampersand: Tom & Jerry
- Less than: 5 < 10
- Greater than: 10 > 5
- Quotes: "Hello" and 'World'

## Collapsible Section Test

### Section 1

This is the content of section 1. It should be collapsible when the feature is enabled.

Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.

### Section 2

This is the content of section 2.

More content here to test the collapsible functionality.

## Back to Top Test

This section should have a "Back to top" link at the end if the feature is enabled.

---

## Conclusion

This test document covers the main features of the converter:

1. Basic Markdown rendering
2. Code block styling with syntax highlighting
3. Output block styling
4. Math rendering (inline and display)
5. Tables
6. XSS prevention
7. Special character escaping
8. Collapsible sections
9. Back to top links
10. Dark/light theme toggle
