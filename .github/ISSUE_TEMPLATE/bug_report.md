---
name: Bug report
about: Create a report to help us improve
title: '[BUG]'
labels: bug
assignees: ''
---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:

1. Configure the library with '...'
2. Call method '....'
3. Access endpoint '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Environment (please complete the following information):**

- OS: [e.g. Ubuntu 20.04, Windows 10]
- Python version [e.g. 3.8.10]
- Library version [e.g. 0.3.0]
- MongoDB version [e.g. 4.4]
- Duo SDK version [e.g. 1.0.0]

**Configuration**
Please provide your configuration (with sensitive information redacted):

```python
db_config = {
    'username': 'redacted',
    'password': 'redacted',
    'host': 'redacted',
    'database': 'auth-db',
    'pool_size': 50
}

# Other configuration...
```

**Performance Impact**
If this is a performance-related issue, please provide relevant metrics:

- Request times before the issue: [e.g. avg 150ms]
- Request times after the issue: [e.g. avg 800ms]
- Cache hit rate: [e.g. 75%]
- User load: [e.g. 100 concurrent users]

**Logs**
Please provide relevant log output if available:

```
Log output here
```

**Additional context**
Add any other context about the problem here.
