# Secure File Vault

A zero-knowledge encrypted file sharing system with end-to-end encryption, built with Python and Flask. This application provides secure file storage and sharing capabilities with features like file versioning, access control, and comprehensive audit logging.

## Features

- 🔐 Zero-knowledge encryption
- 🔒 End-to-end encryption for all files
- 👥 User authentication and access control
- 📂 File versioning
- 🔄 Secure file sharing capabilities
- 📝 Comprehensive audit logging
- 🌐 Web-based interface

## Quick Start with Docker

1. Clone the repository:
```bash
git clone https://github.com/Klima42/6secure-file-vault.git
cd secure-file-vault
```

2. Build and run with Docker:
```bash
docker-compose build
docker-compose up
```

3. Access the application at `http://localhost:5000`

## Manual Installation

1. Create and activate virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python -m venv venv
source venv/bin/activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create .env file in the root directory:
```
SECRET_KEY=your-secret-key-here
```

4. Initialize the database:
```python
python
>>> from app import create_app, db
>>> app = create_app()
>>> with app.app_context():
...     db.create_all()
>>> exit()
```

5. Run the application:
```bash
python run.py
```

## Docker Commands

```bash
# Build and start containers
docker-compose up -d

# View logs
docker-compose logs -f

# Stop containers
docker-compose down

# Rebuild after changes
docker-compose up -d --build
```

## Project Structure

```
secure_file_vault/
├── app/
│   ├── __init__.py
│   ├── routes.py
│   ├── models.py
│   ├── forms.py
│   ├── crypto.py
│   └── templates/
├── config.py
├── requirements.txt
├── docker-compose.yml
├── Dockerfile
└── run.py
```

## Security Features

- Password-derived key generation using PBKDF2
- Secure file encryption using Fernet
- Unique salt for each file
- Secure password hashing
- Protection against unauthorized access

## File Operations

- **Upload**: Select a file and set an encryption password
- **Download**: Enter the correct password to decrypt and download
- **Share**: Share files with other users while maintaining encryption
- **Audit**: View complete access and modification history

## Development

Want to contribute? Great!

1. Fork the repo
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## Security Best Practices

- Always use strong, unique passwords for file encryption
- Never share encryption passwords through unsecured channels
- Regularly check the audit logs for unauthorized access attempts
- Log out when not actively using the system

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Future Improvements

- [ ] Add file versioning system
- [ ] Implement file expiry dates
- [ ] Add two-factor authentication
- [ ] Create mobile application
- [ ] Add real-time collaboration features
- [ ] Implement Docker volume backups
- [ ] Add health check endpoints
- [ ] Implement rate limiting

## Tech Stack

- Backend: Python/Flask
- Database: SQLAlchemy
- Authentication: Flask-Login
- Encryption: cryptography.fernet
- Frontend: Bootstrap 5
- Containerization: Docker
