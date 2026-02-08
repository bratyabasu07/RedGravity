# Contributing to RedGravity 🚀

Thank you for your interest in contributing to RedGravity! We welcome contributions from the community.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Go version, etc.)

### Suggesting Features

Feature requests are welcome! Please:
- Check if the feature already exists
- Describe the use case clearly
- Explain why it would benefit users

### Pull Requests

We accept pull requests! Here's how:

1. **Fork the Repository**
   ```bash
   git clone https://github.com/bratyabasu07/RedGravity.git
   cd RedGravity
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**
   - Follow Go best practices
   - Add tests for new features
   - Update documentation as needed
   - Keep commits atomic and well-described

4. **Test Your Changes**
   ```bash
   go build -o redgravity cmd/main.go
   go test ./...
   ```

5. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat: add amazing feature"
   ```

6. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then create a Pull Request on GitHub.

## Code Guidelines

### Go Style
- Follow standard Go formatting (`gofmt`)
- Use meaningful variable names
- Add comments for complex logic
- Keep functions focused and small

### Commit Messages
Use conventional commits format:
- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Test additions/changes
- `chore:` - Maintenance tasks

Example: `feat: add GreyNoise API integration`

## Development Setup

### Prerequisites
- Go 1.21 or higher
- Git
- Access to API keys for testing

### Local Development
```bash
# Install dependencies
go mod tidy

# Build
go build -o redgravity cmd/main.go

# Run tests
go test ./...

# Run with your changes
./redgravity -t example.com -m normal
```

## Areas We Need Help With

- [ ] **API Integrations**: Adding new intelligence sources
- [ ] **Testing**: Writing unit and integration tests
- [ ] **Documentation**: Improving README, adding examples
- [ ] **Performance**: Optimizing scan speed
- [ ] **Features**: Database persistence, ML integration, WebUI

## Code Review Process

1. Maintainers will review your PR
2. Address any feedback or requested changes
3. Once approved, we'll merge your contribution
4. Your contribution will be credited in releases

## Questions?

- Open an issue for questions
- Check existing issues and PRs first
- Be respectful and constructive

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for making RedGravity better!** 🔥

*Built by: Elliot Jr (Bratyabasu07) & DefroX556*
