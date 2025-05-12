from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="duo_flask_auth",
    version="0.4.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "Flask>=2.0.0",
        "Flask-Login>=0.5.0",
        "Flask-WTF>=1.0.0",  # Added for CSRF protection
        "duo-universal>=1.0.0",
        "pymongo>=4.0.0",
        "certifi>=2021.10.8",
        "Werkzeug>=2.0.0",
    ],
    author="Aaron Davis",
    author_email="aaron.e.davis@gmail.com",
    description="Flask authentication library with Duo MFA support, enhanced security features, flexibility, and performance optimizations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords="flask, authentication, duo, mfa, security, performance",
    url="https://github.com/yourusername/duo-flask-auth",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/duo-flask-auth/issues",
        "Documentation": "https://github.com/yourusername/duo-flask-auth#readme",
        "Source Code": "https://github.com/yourusername/duo-flask-auth",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Framework :: Flask",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    package_data={
        "duo_flask_auth": ["templates/*.html"],
    },
)
