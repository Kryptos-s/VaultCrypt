# Contributing to VaultCrypt

First off, thank you for considering contributing to VaultCrypt! It's people like you that make VaultCrypt a great tool.

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

**Bug Report Template:**
```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce:
1. Go to '...'
2. Click on '...'
3. See error

**Expected behavior**
What you expected to happen.

**Screenshots**
If applicable, add screenshots.

**Environment:**
 - OS: [e.g. Windows 11]
 - VaultCrypt Version: [e.g. 1.0.0]
 - Qt Version: [e.g. 5.15.2]

**Additional context**
Any other context about the problem.
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. Create an issue and provide:
- Clear title and description
- Explain why this enhancement would be useful
- Possibly include mockups or examples

### Pull Requests

1. **Fork the repo** and create your branch from `main`
2. **Follow the coding style** (see below)
3. **Add tests** if you've added code that should be tested
4. **Ensure tests pass**
5. **Update documentation** as needed
6. **Write clear commit messages**

## Development Setup

See [BUILDING.md](BUILDING.md) for detailed setup instructions.

**Quick setup:**
```bash
git clone https://github.com/yourusername/VaultCrypt.git
cd VaultCrypt
cmake -B build -S .
cmake --build build
```

## Coding Style

### C++ Style

- **Standard:** C++17
- **Naming:**
  - Classes: `PascalCase` (e.g., `AESGCMCipher`)
  - Functions: `snake_case` (e.g., `encrypt_password`)
  - Variables: `snake_case` (e.g., `plaintext_data`)
  - Constants: `UPPER_CASE` (e.g., `KEY_SIZE`)
- **Formatting:**
  - Indent: 4 spaces (no tabs)
  - Line length: 100 characters max
  - Braces: Same line for functions, next line for control structures

**Example:**
```cpp
class MyClass {
public:
    void do_something(int value) {
        if (value > 0) {
            process_value(value);
        }
    }
    
private:
    int m_member_variable;
};
```

### Qt Style

- Use Qt naming conventions for Qt-specific code
- Signals/slots use camelCase: `onButtonClicked()`
- UI elements use descriptive names: `encryptButton`, `passwordEdit`

### Git Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues and pull requests

**Example:**
```
Add XChaCha20 encryption support

- Implement ChaCha20Poly1305Cipher class
- Add unit tests for new cipher
- Update documentation

Fixes #123
```

## Testing

Run tests before submitting:
```bash
cd build
ctest --output-on-failure
```

Add tests for new features:
```cpp
TEST_CASE("Encryption produces valid output") {
    // Test code here
}
```

## Documentation

- Update README.md if adding features
- Add docstrings to public APIs:
```cpp
/**
 * @brief Encrypts data using AES-256-GCM
 * @param key 256-bit encryption key
 * @param plaintext Data to encrypt
 * @return Encrypted ciphertext with authentication tag
 */
SecureBytes encrypt(const SecureBytes& key, const SecureBytes& plaintext);
```

## Review Process

1. Submit pull request
2. Maintainers review code
3. Address feedback
4. Once approved, maintainers merge

**Review checklist:**
- [ ] Code follows style guide
- [ ] Tests pass
- [ ] Documentation updated
- [ ] No security issues
- [ ] Performance acceptable

## Community

- Be respectful and inclusive
- Help others learn
- Give constructive feedback
- Celebrate contributions

## Questions?

Feel free to ask questions in:
- [GitHub Discussions](https://github.com/Kryptos-s/VaultCrypt/discussions)
- [Issue tracker](https://github.com/Kryptos-s/VaultCrypt/issues)

Thank you for contributing! 🎉
