# Testing SSL-Checkup

This document describes the comprehensive testing setup for the SSL-Checkup package.

## Test Overview

The project maintains **151 tests** with **95% code coverage**, ensuring reliability and maintainability.

### Test Structure

```
tests/
├── conftest.py              # Pytest fixtures and configuration
├── test_cli.py              # CLI argument parsing (20 tests)
├── test_connection.py       # SSL connection functionality (9 tests)
├── test_parser.py           # Certificate parsing logic (23 tests)
├── test_display.py          # Output formatting (13 tests)
├── test_formatting.py       # Text formatting utilities (26 tests)
├── test_exceptions.py       # Error handling (15 tests)
├── test_main.py             # Main application flow (25 tests)
└── test_integration.py      # End-to-end CLI testing (20 tests)
```

## Quick Start

### Install Test Dependencies
```bash
# Using uv (recommended)
uv sync

# Using pip
pip install -e ".[test]"
```

### Run Tests
```bash
# All tests
make test

# With coverage
make test-coverage

# Specific categories
make test-unit           # Unit tests only
make test-integration    # Integration tests only

# All quality checks
make check-all
```

## Advanced Testing

### Pytest Commands

```bash
# Run all tests with verbose output
pytest -v

# Run specific test file
pytest tests/test_cli.py

# Run specific test
pytest tests/test_cli.py::TestCreateParser::test_parser_creation

# Run with coverage
pytest --cov=ssl_checkup --cov-report=term-missing

# Generate HTML coverage report
pytest --cov=ssl_checkup --cov-report=html

# Run only unit tests
pytest -m "not integration"

# Run only integration tests
pytest -m integration
```

### Multi-Environment Testing

```bash
# Test across multiple Python versions
tox

# Test specific environment
tox -e py311

# Run linting
tox -e lint

# Run security checks
tox -e security
```

## Test Features

### Key Fixtures (conftest.py)
- `sample_cert` - Valid certificate data for testing
- `expired_cert` - Expired certificate data
- `soon_expiring_cert` - Certificate expiring soon
- `sample_pem_cert` - PEM format certificate
- `mock_cert_info` - Mock connection information

### Testing Strategy
- **Unit Tests**: Individual function/method testing with mocks
- **Integration Tests**: End-to-end CLI workflow testing
- **Error Handling**: Exception and error condition testing
- **Edge Cases**: Boundary conditions and malformed data testing

### Coverage Goals
- **Target**: 95% code coverage
- **Current**: 95% achieved
- **Reports**: HTML, XML, and terminal coverage reports
- **Branch Coverage**: Enabled for comprehensive testing

## Development Workflow

### Writing Tests

**Test Naming Convention:**
```python
# Test files: test_<module>.py
# Test classes: Test<ClassName>
# Test methods: test_<functionality>

class TestClassName:
    """Test class description."""
    
    def test_basic_functionality(self):
        """Test basic functionality."""
        # Arrange, Act, Assert
        
    def test_edge_case(self):
        """Test edge case handling."""
        
    def test_error_handling(self):
        """Test error conditions."""
```

### Best Practices
1. **Isolation** - Each test is independent
2. **Mocking** - External dependencies are mocked
3. **Assertions** - Clear and specific assertions
4. **Coverage** - Test both success and failure cases
5. **Documentation** - Descriptive test names and docstrings

### Debugging Tests

```bash
# Run single test with debug output
pytest tests/test_cli.py::TestCreateParser::test_parser_creation -v -s

# Drop into debugger on failure
pytest --pdb

# Enable logging
pytest --log-cli-level=DEBUG
```

## CI/CD Integration

### GitHub Actions
- **Multi-OS Testing**: Ubuntu, Windows, macOS
- **Multi-Python**: Python 3.11, 3.12
- **Quality Checks**: Tests, linting, security scanning
- **Coverage**: Automatic coverage reporting

### Local CI Simulation
```bash
# Run same checks as CI
make ci
```

## Contributing

When adding new features:
1. **Write tests first** (TDD approach)
2. **Ensure all tests pass**: `make test`
3. **Maintain coverage**: Target 95%+
4. **Test edge cases**: Include error conditions
5. **Update documentation**: Add test descriptions

## Troubleshooting

### Common Issues
- **Import errors**: Install package in development mode (`pip install -e .`)
- **Mock failures**: Check mock setup and expectations
- **Coverage gaps**: Use `--cov-report=html` to identify missing coverage
- **Slow tests**: Use `-m "not integration"` for faster unit tests

### Getting Help
- Check test output for detailed error messages
- Use `pytest --tb=long` for full tracebacks
- Review test fixtures and mocks in `conftest.py`
- Consult the [pytest documentation](https://docs.pytest.org/)
