# Directory Structure
"""
secure_file_share/
├── backend/
│   ├── __init__.py
│   ├── app.py              # FastAPI application
│   ├── models.py           # Database models
│   ├── crypto.py           # Cryptographic operations
│   ├── auth.py             # Authentication logic
│   └── storage.py          # File storage handling
├── frontend/
│   ├── src/
│   │   ├── App.js
│   │   └── components/
└── requirements.txt
"""

# backend/crypto.py
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import base64
import os

class CryptoManager:
    def __init__(self):
        self.salt = os.urandom(16)
        
    def generate_key_pair(self):
        """Generate RSA key pair for asymmetric encryption"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def derive_key(self, password: str) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt_file(self, file_data: bytes, password: str) -> tuple[bytes, bytes]:
        """Encrypt file data using key derived from password"""
        key = self.derive_key(password)
        f = Fernet(key)
        encrypted_data = f.encrypt(file_data)
        return encrypted_data, self.salt
    
    def decrypt_file(self, encrypted_data: bytes, password: str, salt: bytes) -> bytes:
        """Decrypt file data using key derived from password"""
        self.salt = salt
        key = self.derive_key(password)
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data

# backend/models.py
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password_hash = Column(String)
    public_key = Column(String)
    files = relationship("File", back_populates="owner")
    
class File(Base):
    __tablename__ = 'files'
    
    id = Column(Integer, primary_key=True)
    filename = Column(String)
    version = Column(Integer, default=1)
    encrypted_data = Column(String)
    salt = Column(String)
    owner_id = Column(Integer, ForeignKey('users.id'))
    owner = relationship("User", back_populates="files")
    created_at = Column(DateTime, default=datetime.utcnow)
    
class FileAccess(Base):
    __tablename__ = 'file_access'
    
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey('files.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    can_read = Column(Boolean, default=True)
    can_write = Column(Boolean, default=False)
    
class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey('files.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    action = Column(String)  # upload, download, share, delete
    timestamp = Column(DateTime, default=datetime.utcnow)

# backend/app.py
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import List
import models
import crypto
from datetime import datetime

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
crypto_manager = crypto.CryptoManager()

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/api/users/register")
async def register_user(username: str, password: str, db: Session = Depends(get_db)):
    private_key, public_key = crypto_manager.generate_key_pair()
    user = models.User(
        username=username,
        password_hash=hash_password(password),
        public_key=public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    )
    db.add(user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/api/files/upload")
async def upload_file(
    file: bytes,
    filename: str,
    password: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    encrypted_data, salt = crypto_manager.encrypt_file(file, password)
    
    file_entry = models.File(
        filename=filename,
        encrypted_data=base64.b64encode(encrypted_data).decode(),
        salt=base64.b64encode(salt).decode(),
        owner_id=current_user.id
    )
    
    db.add(file_entry)
    db.commit()
    
    # Log the upload
    audit_log = models.AuditLog(
        file_id=file_entry.id,
        user_id=current_user.id,
        action="upload"
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "File uploaded successfully", "file_id": file_entry.id}

@app.get("/api/files/{file_id}")
async def download_file(
    file_id: int,
    password: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    file = db.query(models.File).filter(models.File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
        
    # Check access permissions
    access = db.query(models.FileAccess).filter(
        models.FileAccess.file_id == file_id,
        models.FileAccess.user_id == current_user.id
    ).first()
    
    if file.owner_id != current_user.id and (not access or not access.can_read):
        raise HTTPException(status_code=403, detail="Access denied")
    
    encrypted_data = base64.b64decode(file.encrypted_data)
    salt = base64.b64decode(file.salt)
    
    try:
        decrypted_data = crypto_manager.decrypt_file(encrypted_data, password, salt)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Decryption failed")
    
    # Log the download
    audit_log = models.AuditLog(
        file_id=file_id,
        user_id=current_user.id,
        action="download"
    )
    db.add(audit_log)
    db.commit()
    
    return {"filename": file.filename, "data": base64.b64encode(decrypted_data).decode()}

@app.post("/api/files/{file_id}/share")
async def share_file(
    file_id: int,
    user_id: int,
    can_read: bool = True,
    can_write: bool = False,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    file = db.query(models.File).filter(models.File.id == file_id).first()
    if not file or file.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    access = models.FileAccess(
        file_id=file_id,
        user_id=user_id,
        can_read=can_read,
        can_write=can_write
    )
    
    db.add(access)
    db.commit()
    
    # Log the share
    audit_log = models.AuditLog(
        file_id=file_id,
        user_id=current_user.id,
        action=f"share with user {user_id}"
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "File shared successfully"}

# Frontend React component for file upload
# frontend/src/components/FileUpload.js
"""
import React, { useState } from 'react';
import axios from 'axios';

const FileUpload = () => {
  const [file, setFile] = useState(null);
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  
  const handleUpload = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('password', password);
    
    try {
      const response = await axios.post('/api/files/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });
      alert('File uploaded successfully!');
    } catch (error) {
      alert('Upload failed: ' + error.message);
    }
    
    setLoading(false);
  };
  
  return (
    <div className="p-4">
      <h2 className="text-xl font-bold mb-4">Upload Encrypted File</h2>
      <form onSubmit={handleUpload} className="space-y-4">
        <div>
          <label className="block mb-2">Select File:</label>
          <input
            type="file"
            onChange={(e) => setFile(e.target.files[0])}
            className="border p-2 w-full"
            required
          />
        </div>
        <div>
          <label className="block mb-2">Encryption Password:</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="border p-2 w-full"
            required
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="bg-blue-500 text-white px-4 py-2 rounded"
        >
          {loading ? 'Uploading...' : 'Upload File'}
        </button>
      </form>
    </div>
  );
};

export default FileUpload;
"""