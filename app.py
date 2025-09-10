from flask import Flask, render_template, request, redirect, url_for, session, flash
#import os
import qrcode
from werkzeug.utils import secure_filename
import cloudinary
import cloudinary.uploader
import cloudinary.api
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import re
import json
import os
from dotenv import load_dotenv
load_dotenv()

# Allowed image file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_valid_name(name):
    return re.fullmatch(r"[A-Za-z\s]+", name)

def is_valid_email(email):
    return re.fullmatch(r"^[\w\.-]+@[\w\.-]+\.com$", email)

app = Flask(__name__)
app.secret_key = os.getenv ('SECRET_KEY')

app.config["MONGO_URI"] = os.getenv ("MONGO_URI")
mongo = PyMongo(app)
try:
    mongo.db.command("ping")
    print("✅ MongoDB connection successful!")
except Exception as e:
    print("❌ MongoDB connection failed:", e)

# Config
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['QR_FOLDER'] = 'static/qrcodes'

# Ensure folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['QR_FOLDER'], exist_ok=True)
os.makedirs('profiles', exist_ok=True)

cloudinary.config(
    cloud_name= os.getenv ('CLOUD_NAME'),
    api_key= os.getenv ('API_KEY'),
    api_secret= os.getenv ('API_SECRET'),
    secure=True
)



# Index route
@app.route('/')
def index():
    return render_template('index.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if not is_valid_name(name):
            flash("❌ Name must contain only alphabets and spaces.")
            return redirect(url_for('register'))

        if not is_valid_email(email):
            flash("❌ Email must end with '.com'.")
            return redirect(url_for('register'))

        if mongo.db.users.find_one({"name": name}):
            flash("User already exists. Please login.")
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password)

        mongo.db.users.insert_one({
            "name": name,
            "email": email,
            "password": hashed_password,
            "files": [],
            "profile": None
        })

        session['username'] = name
        flash("Registration successful! Please fill your health profile.")
        return redirect(url_for('health_profile', username=name))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if not is_valid_name(name):
            flash("❌ Name must contain only alphabets and spaces.")
            return redirect(url_for('login'))

        if not is_valid_email(email):
            flash("❌ Email must end with '.com'.")
            return redirect(url_for('login'))

        user = mongo.db.users.find_one({"name": name})

        if user and user.get('email') == email and check_password_hash(user.get('password', ''), password):
            session['username'] = name
            flash('Login successful!')
            profile = user.get("profile")
            if profile:
                return redirect(url_for('upload_page', username=name))
            else:
                return redirect(url_for('health_profile', username=name))
        else:
            flash("Invalid name, email, or password.")
            return redirect(url_for('login'))

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))



# Health profile route
@app.route('/health_profile/<username>', methods=['GET', 'POST'])
def health_profile(username):
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('login'))

    if request.method == 'POST':
        profile = {
            "name": request.form['name'],
            "age": int(request.form['age']),
            "blood_group": request.form['blood_group'],
            "allergies": [a.strip() for a in request.form['allergies'].split(',')],
            "insurance": {
                "company": request.form['insurance_company'],
                "policy_number": request.form['policy_number']
            },
            "emergency_contact": request.form['emergency_contact'],
            "aadhar_id": request.form['aadhar_id']
        }

        mongo.db.users.update_one(
            {"name": username},
            {"$set": {"profile": profile}}
        )

        flash("✅ Health profile saved!")
        return redirect(url_for('upload_page', username=username))

    return render_template('health_profile.html', username=username)

# Upload page
@app.route('/upload/<username>')
def upload_page(username):
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('login'))
    return render_template('upload.html', username=username)

# File upload
@app.route('/upload_file/<username>', methods=['POST'])
def upload_file(username):
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('login'))

    files = request.files.getlist('file')

    for file in files:
        if file and allowed_file(file.filename):
            upload_result = cloudinary.uploader.upload(
                file,
                folder=f"healthqr/{username}/",
                resource_type="image"
            )
            file_url = upload_result.get("secure_url")
            mongo.db.users.update_one(
                {"name": username},
                {"$push": {"files": file_url}},
                upsert=True
            )

    return redirect(url_for('generate_qr', username=username))

# View profile
@app.route('/view_profile/<username>')
def view_profile(username):
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({"name": username})
    if not user or not user.get("profile"):
        flash("⚠️ Health profile not found. Please fill it first.")
        return redirect(url_for('health_profile', username=username))

    profile = user["profile"]
    return render_template('view_profile.html', username=username, profile=profile)

# Generate QR code
@app.route('/generate_qr/<username>')
def generate_qr(username):
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('login'))

    qr_url = url_for('scan_profile', username=username, _external=True)
    qr_path = os.path.join(app.config['QR_FOLDER'], f"{username}.png")

    img = qrcode.make(qr_url)
    img.save(qr_path)

    return render_template('qr.html', username=username, qr_path=qr_path)

# Scan profile
@app.route('/scan/<username>')
def scan_profile(username):
    user = mongo.db.users.find_one({"name": username})
    if not user:
        return "User not found.", 404

    profile = user.get("profile")
    files = user.get("files", [])

    return render_template('scan_profile.html', profile=profile, files=files, username=username)

# View reports
@app.route('/view_reports/<username>')
def view_reports(username):
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('login'))

    user = mongo.db.users.find_one({"name": username})
    files = user.get("files", []) if user else []
    return render_template('view_reports.html', username=username, files=files)

# Delete file
@app.route('/delete_file/<username>', methods=['POST'])
def delete_file(username):
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('login'))

    file_url = request.form.get('file_url')

    if file_url:
        mongo.db.users.update_one(
            {"name": username},
            {"$pull": {"files": file_url}}
        )

    flash("File deleted successfully.")
    return redirect(url_for('view_reports', username=username))


if __name__ == "__main__":
    app.run(debug=True)
    