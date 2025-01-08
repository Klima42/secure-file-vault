from flask import Blueprint, render_template, flash, redirect, url_for, request, send_file
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, File, AuditLog
from app.forms import LoginForm, RegistrationForm, UploadForm, ShareForm
from app.crypto import Crypto
from werkzeug.security import generate_password_hash, check_password_hash
import io

main = Blueprint('main', __name__)
auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        flash('Invalid username or password')
    return render_template('login.html', title='Login', form=form)

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=generate_password_hash(form.password.data)
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('auth.login'))
    return render_template('register.html', title='Register', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@main.route('/')
@main.route('/dashboard')
@login_required
def dashboard():
    files = File.query.filter_by(owner_id=current_user.id).all()
    shared_files = File.query.filter(
        File.shared_with.contains(str(current_user.id))
    ).all()
    return render_template('dashboard.html', 
                         title='Dashboard',
                         files=files, 
                         shared_files=shared_files)

@main.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        file_data = form.file.data.read()
        try:
            encrypted_data, salt = Crypto.encrypt_file(file_data, form.password.data)
            
            file = File(
                filename=form.file.data.filename,
                encrypted_data=encrypted_data,
                salt=salt,
                owner_id=current_user.id
            )
            db.session.add(file)
            
            # Log the upload
            log = AuditLog(
                file_id=file.id,
                user_id=current_user.id,
                action='upload',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash('File uploaded successfully')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            flash(f'Upload failed: {str(e)}')
            return redirect(url_for('main.upload'))
            
    return render_template('upload.html', title='Upload File', form=form)

@main.route('/download/<int:file_id>', methods=['POST'])
@login_required
def download(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id and current_user.id not in file.get_shared_users():
        flash('Access denied')
        return redirect(url_for('main.dashboard'))
    
    password = request.form.get('password')
    if not password:
        flash('Password required')
        return redirect(url_for('main.dashboard'))
    
    try:
        decrypted_data = Crypto.decrypt_file(file.encrypted_data, password, file.salt)
        
        # Log the download
        log = AuditLog(
            file_id=file.id,
            user_id=current_user.id,
            action='download',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        return send_file(
            io.BytesIO(decrypted_data),
            download_name=file.filename,
            as_attachment=True
        )
    except Exception as e:
        flash('Decryption failed - wrong password')
        return redirect(url_for('main.dashboard'))

@main.route('/share/<int:file_id>', methods=['GET', 'POST'])
@login_required
def share(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('Access denied')
        return redirect(url_for('main.dashboard'))
    
    form = ShareForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            file.share_with_user(user.id)
            
            # Log the share
            log = AuditLog(
                file_id=file.id,
                user_id=current_user.id,
                action=f'shared with {user.username}',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            flash(f'File shared with {user.username}')
            return redirect(url_for('main.dashboard'))
        flash('User not found')
    return render_template('share.html', title='Share File', form=form, file=file)

@main.route('/audit/<int:file_id>')
@login_required
def audit_log(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('Access denied')
        return redirect(url_for('main.dashboard'))
        
    logs = AuditLog.query.filter_by(file_id=file_id).order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit.html', title='Audit Log', file=file, logs=logs)