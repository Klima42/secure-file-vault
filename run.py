from app import create_app, db
from app.models import User, File, AuditLog

app = create_app()

@app.shell_context_processor
def make_shell_context():
    return {
        'db': db,
        'User': User,
        'File': File,
        'AuditLog': AuditLog
    }

if __name__ == '__main__':
    app.run(debug=True)