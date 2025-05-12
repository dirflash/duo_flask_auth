# Contributing to Duo Flask Auth

Thank you for considering contributing to Duo Flask Auth! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and considerate of others.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to see if the problem has already been reported. When creating a bug report, include as many details as possible:

- Use a clear and descriptive title
- Describe the exact steps to reproduce the problem
- Describe the behavior you observed and the behavior you expected
- Include details about your environment (OS, Python version, package versions)
- Include screenshots or code examples if possible

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- Use a clear and descriptive title
- Provide a detailed description of the suggested enhancement
- Explain why this enhancement would be useful to most users
- Include any relevant examples or mockups

### Pull Requests

- Fill in the required template
- Follow the code style of the project
- Include tests for your changes
- Update the documentation for any API changes
- End files with a newline
- Use descriptive commit messages
- Make sure all tests pass

## Development Setup

1. Fork the repository
2. Clone your fork locally
3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```
4. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   pip install pytest pytest-cov black isort
   ```
5. Create a branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Testing

We use pytest for testing. To run tests:

```bash
pytest
```

For test coverage:

```bash
pytest --cov=duo_flask_auth
```

## Code Style

We use Black for code formatting and isort for import sorting. Before submitting a pull request, please run:

```bash
black duo_flask_auth tests
isort duo_flask_auth tests
```

## Documentation

All new features should include appropriate documentation. Update the README.md and other documentation files as needed.

## Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests after the first line

## Performance Considerations

If your changes affect performance, please include:

1. Before and after benchmarks
2. Explanation of the performance impact
3. Considerations for high-traffic environments

## Pull Request Process

1. Update the README.md and documentation with details of changes
2. Update the CHANGELOG.md with your changes
3. The versioning scheme we use is [SemVer](http://semver.org/)
4. You may merge the Pull Request once you have the sign-off of two other developers, or if you don't have permission to do that, you may request the reviewers to merge it for you

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.
