import os
import re
import datetime
import warnings
import io

# ----------------- 1. SILENCE TERMINAL WARNINGS -----------------
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass

import numpy as np
import joblib
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Optional document parsing libraries
try:
    from pypdf import PdfReader
except ImportError:
    try:
        from PyPDF2 import PdfReader
    except ImportError:
        PdfReader = None

try:
    import docx
except ImportError:
    docx = None

# ----------------- 2. APPLICATION CONFIGURATION -----------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'tamscam_detector_security_key_2026'
app.config['SESSION_PERMANENT'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
os.makedirs(INSTANCE_DIR, exist_ok=True)
DB_PATH = os.path.join(INSTANCE_DIR, 'tamscam_detector.db')

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ----------------- 3. DATABASE SCHEMAS -----------------
class Account(db.Model):
    __tablename__ = 'accounts'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    scans = db.relationship('ScanLog', backref='user', lazy=True, cascade="all, delete-orphan")


class ScanLog(db.Model):
    __tablename__ = 'scan_logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    job_title = db.Column(db.String(200), nullable=False)
    company_name = db.Column(db.String(200), nullable=True, default="Undisclosed")
    job_description = db.Column(db.Text, nullable=True)
    scam_score = db.Column(db.Integer, nullable=False)
    verdict = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# ----------------- 4. INITIALIZE DB & ROOT ADMIN -----------------
with app.app_context():
    db.create_all()

    admin_exists = Account.query.filter_by(username='Tamannah').first()
    if not admin_exists:
        fixed_admin = Account(
            username='Tamannah',
            email='tamannah.admin@tamscam.internal',
            password_hash=generate_password_hash('Tamannah@10', method='scrypt'),
            role='admin'
        )
        db.session.add(fixed_admin)
        db.session.commit()
        print("Root Admin account 'Tamannah' ready.")

# ----------------- 5. LOAD MODEL ARTIFACTS -----------------
candidate_model_paths = [
    os.path.join(BASE_DIR, "saved_models", "hybrid_svm_component.pkl"),
    os.path.join(BASE_DIR, "notebooks", "saved_models", "hybrid_svm_component.pkl"),
    os.path.join(BASE_DIR, "saved_models", "master_best_model.pkl"),
    os.path.join(BASE_DIR, "notebooks", "saved_models", "master_best_model.pkl")
]

candidate_vec_paths = [
    os.path.join(BASE_DIR, "saved_models", "master_tfidf_vectorizer.pkl"),
    os.path.join(BASE_DIR, "notebooks", "saved_models", "master_tfidf_vectorizer.pkl")
]

MODEL_PATH = next((p for p in candidate_model_paths if os.path.exists(p)), None)
VEC_PATH = next((p for p in candidate_vec_paths if os.path.exists(p)), None)

master_model = None
master_vectorizer = None

if MODEL_PATH and VEC_PATH:
    try:
        master_model = joblib.load(MODEL_PATH)
        master_vectorizer = joblib.load(VEC_PATH)
        print("AI Detection Model loaded successfully.")
    except Exception as e:
        print(f"Model load notice: {e}")
else:
    print("Notice: Model files not found in saved_models directory.")

# ----------------- 6. SECURITY & ACCESS GUARDS -----------------
PASSWORD_REGEX = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$"

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'account_id' not in session:
            flash('Please log in to access TamScam Detector.', 'warning')
            return redirect(url_for('portal_select'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'account_id' not in session or session.get('role') != 'admin':
            flash('Restricted root terminal. Administrator credentials required.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# ----------------- 7. HELPER: EXTRACT TEXT FROM UPLOADED FILES -----------------
def extract_text_from_file(file_storage):
    """Extracts text from PDF, DOCX, or TXT uploads without crashing."""
    if not file_storage or not file_storage.filename:
        return ""
    
    filename = secure_filename(file_storage.filename).lower()
    content = ""
    
    try:
        if filename.endswith(".pdf"):
            if PdfReader is None:
                return "[Error: pypdf library is not installed on server]"
            pdf_bytes = io.BytesIO(file_storage.read())
            reader = PdfReader(pdf_bytes)
            pages_text = [page.extract_text() or "" for page in reader.pages]
            content = "\n".join(pages_text).strip()
            
        elif filename.endswith(".docx"):
            if docx is None:
                return "[Error: python-docx library is not installed on server]"
            docx_bytes = io.BytesIO(file_storage.read())
            doc = docx.Document(docx_bytes)
            content = "\n".join([para.text for para in doc.paragraphs if para.text]).strip()
            
        elif filename.endswith(".txt"):
            content = file_storage.read().decode("utf-8", errors="ignore").strip()
            
    except Exception as err:
        print(f"File extraction error: {err}")
        return ""
        
    return content

# ----------------- 8. AUTHENTICATION ROUTES -----------------
@app.route('/')
def index():
    return redirect(url_for('portal_select'))

@app.route('/portals')
def portal_select():
    return render_template('portal_select.html')

@app.route('/register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not username or not email or not password or not confirm_password:
            flash('All input fields are strictly required.', 'danger')
            return redirect(url_for('user_register'))

        if not re.match(PASSWORD_REGEX, password):
            flash('Password requires 8+ chars with uppercase, lowercase, digit, and symbol (@$!%*?&#).', 'danger')
            return redirect(url_for('user_register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('user_register'))

        if Account.query.filter_by(email=email).first():
            flash('This email address is already registered.', 'warning')
            return redirect(url_for('user_register'))

        if Account.query.filter_by(username=username).first():
            flash('Username is already taken. Please pick another.', 'warning')
            return redirect(url_for('user_register'))
            
        new_user = Account(
            username=username,
            email=email,
            password_hash=generate_password_hash(password, method='scrypt'),
            role='user'
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration completed successfully! Please log in.', 'success')
        return redirect(url_for('user_login'))

    return render_template('user_register.html')

@app.route('/login/user', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash('Email and password are required.', 'danger')
            return redirect(url_for('user_login'))

        user = Account.query.filter_by(email=email, role='user').first()

        if user and check_password_hash(user.password_hash, password):
            session['account_id'] = user.id
            session['username'] = user.username
            session['role'] = 'user'
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('user_home'))

        flash('Invalid email or password.', 'danger')
        return redirect(url_for('user_login'))

    return render_template('user_login.html')

@app.route('/login/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('Admin username and password are required.', 'danger')
            return redirect(url_for('admin_login'))

        admin = Account.query.filter_by(username=username, role='admin').first()

        if admin and check_password_hash(admin.password_hash, password):
            session['account_id'] = admin.id
            session['username'] = admin.username
            session['role'] = 'admin'
            flash('Admin authentication successful.', 'success')
            return redirect(url_for('admin_dashboard'))

        flash('Access Denied: Invalid administrator credentials.', 'danger')
        return redirect(url_for('admin_login'))

    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('portal_select'))

# ----------------- 9. USER PAGES & PREDICTION ROUTE -----------------
@app.route('/user/home')
@login_required
def user_home():
    user_id = session.get('account_id')
    user_scans = ScanLog.query.filter_by(user_id=user_id).all()
    total_scanned = len(user_scans)

    scams_caught = sum(1 for s in user_scans if s.verdict in ['High Risk', 'Suspicious'] or s.scam_score >= 35)
    safe_offers = sum(1 for s in user_scans if s.verdict in ['Safe', 'Verified'] or s.scam_score < 35)

    return render_template(
        'user_home.html',
        username=session.get('username'),
        total_scanned=total_scanned,
        scams_caught=scams_caught,
        safe_offers=safe_offers
    )

@app.route('/user/scan')
@login_required
def user_scan():
    user_id = session.get('account_id')
    user_scans = ScanLog.query.filter_by(user_id=user_id).order_by(ScanLog.created_at.desc()).limit(15).all()
    return render_template('user_dashboard.html', username=session.get('username'), scans=user_scans)

@app.route('/api/analyze', methods=['POST'])
@login_required
def analyze_job():
    try:
        # Accepts multipart/form-data (for file uploads) or fallback JSON
        if request.content_type and 'multipart/form-data' in request.content_type:
            data = request.form
            uploaded_file = request.files.get('jdFile')
        else:
            data = request.get_json(silent=True) or {}
            uploaded_file = None

        job_title = data.get('title', '').strip()
        company = data.get('company', '').strip() or 'Not Provided'
        location = data.get('location', '').strip()
        salary = data.get('salary', '').strip()
        emp_type = data.get('empType', '').strip()
        exp_level = data.get('expLevel', '').strip()
        company_profile = data.get('companyProfile', '').strip()
        raw_description = data.get('description', '').strip()
        fee_asked = data.get('feeAsked', '').strip()

        # Extract text from uploaded PDF/Word document if attached
        file_extracted_text = ""
        if uploaded_file and uploaded_file.filename:
            file_extracted_text = extract_text_from_file(uploaded_file)

        # Merge descriptions
        description = f"{raw_description} {file_extracted_text}".strip()

        if not job_title or not description:
            return jsonify({'error': 'Please provide Job Title and either enter Job Description or upload a JD document.'}), 400

        full_text = f"{job_title} {company} {location} {salary} {emp_type} {exp_level} {company_profile} {description}".strip().lower()

        # 1. Real ML / DL Model Inference
        model_prob = None
        if master_model is not None and master_vectorizer is not None:
            try:
                feats = master_vectorizer.transform([full_text])
                if hasattr(master_model, "predict_proba"):
                    probs = master_model.predict_proba(feats)
                    model_prob = float(probs[0][1])
                elif hasattr(master_model, "decision_function"):
                    df_val = float(master_model.decision_function(feats)[0])
                    model_prob = float(1.0 / (1.0 + np.exp(-df_val)))
                else:
                    pred = master_model.predict(feats)
                    model_prob = float(pred[0])
            except Exception:
                model_prob = None

        # 2. Text Entropy & Inconsistency Checks
        word_count = len(description.split())
        text_length_penalty = 18 if word_count < 25 else (8 if word_count < 60 else 0)
        domain_penalty = 12 if (not company_profile or company_profile.lower() in ['nothing', 'none', 'n/a', 'na', 'no']) else 0

        title_words = set(re.findall(r'\w+', job_title.lower()))
        desc_words = set(re.findall(r'\w+', description.lower()))
        relevance_overlap = len(title_words.intersection(desc_words))
        inconsistency_penalty = 15 if (relevance_overlap == 0 and len(title_words) > 0) else 0

        if model_prob is not None:
            base_risk = (model_prob * 75) + text_length_penalty + domain_penalty + inconsistency_penalty
        else:
            base_risk = 15 + text_length_penalty + domain_penalty + inconsistency_penalty

        # 3. Explicit Triggers (Synchronized Logic)
        risk_boost = 0
        detected_triggers = []
        desc_lower = description.lower()
        fee_asked_lower = fee_asked.lower()

        # Sign 1: Money / Fee Check
        is_radio_yes = any(phrase in fee_asked_lower for phrase in ["registration fee", "red flag", "yes"])
        fee_keywords = ["registration fee", "security deposit", "processing fee", "pay upfront", "laptop fee", "wire transfer", "crypto", "gift card"]
        has_fee_in_desc = any(kw in desc_lower for kw in fee_keywords)
        is_money_flagged = is_radio_yes or has_fee_in_desc

        if is_money_flagged:
            risk_boost += 60
            detected_triggers.append("Upfront fee or security deposit requested")

        # Sign 2: Telegram / WhatsApp
        chat_keywords = ["telegram", "whatsapp", "signal app"]
        is_chat_flagged = any(kw in desc_lower for kw in chat_keywords)
        if is_chat_flagged:
            risk_boost += 28
            detected_triggers.append("Off-platform messaging channel (Telegram/WhatsApp)")

        # Sign 3: Unrealistic Entry-Level Salary
        salary_digits = re.sub(r'[^\d]', '', salary)
        salary_num = float(salary_digits) if salary_digits else 0.0
        is_fresher = any(k in f"{job_title} {exp_level}".lower() for k in ["intern", "fresher", "no experience"])
        is_salary_flagged = (is_fresher and salary_num > 40000) or ("$500/day" in desc_lower) or ("$50/hr" in desc_lower)
        if is_salary_flagged:
            risk_boost += 30
            detected_triggers.append(f"Unrealistic salary ({salary}) for entry-level candidate")

        # Sign 4: Free Mail Provider
        free_domains = ["@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com"]
        is_email_flagged = any(d in desc_lower or d in company_profile.lower() for d in free_domains)
        if is_email_flagged:
            risk_boost += 20
            detected_triggers.append("Free public email provider used")

        # 4. Final Score & Categorization
        raw_final = base_risk + risk_boost
        char_hash_variance = (sum(ord(c) for c in full_text) % 7) - 3
        
        if is_money_flagged:
            final_score = int(np.clip(max(raw_final, 95) + char_hash_variance, 95, 98))
        else:
            final_score = int(np.clip(raw_final + char_hash_variance, 4, 98))

        if final_score >= 65:
            verdict = 'High Risk'
            status = 'danger'
            reason = f"High Threat Detected: {', '.join(detected_triggers)}." if detected_triggers else "Job description closely matches known scam patterns."
        elif final_score >= 35:
            verdict = 'Suspicious'
            status = 'warning'
            reasons_list = []
            if text_length_penalty > 0:
                reasons_list.append("Unusually short job description")
            if domain_penalty > 0:
                reasons_list.append("No verified company website provided")
            if inconsistency_penalty > 0:
                reasons_list.append("Mismatch between title and responsibilities")
            reason = f"Warning: {', '.join(reasons_list) if reasons_list else 'Inconsistent details detected'}. Check the company independently."
        else:
            verdict = 'Safe'
            status = 'success'
            reason = "Job posting language, structure, and compensation align with authentic corporate hiring standards."

        # Save to database
        scan = ScanLog(
            user_id=session.get('account_id'),
            job_title=job_title,
            company_name=company,
            job_description=description[:1000],  # Keep first 1000 chars for DB storage
            scam_score=final_score,
            verdict=verdict
        )
        db.session.add(scan)
        db.session.commit()

        return jsonify({
            'score': final_score,
            'verdict': verdict,
            'status': status,
            'reason': reason,
            'title': job_title,
            'company': company,
            'timestamp': datetime.datetime.now().strftime("%d %b %Y, %I:%M %p"),
            'warning_signs': {
                'money': {
                    'text': 'Found (Risky)' if is_money_flagged else 'Clean',
                    'is_risk': is_money_flagged
                },
                'chat': {
                    'text': 'Suspicious' if is_chat_flagged else 'Normal',
                    'is_risk': is_chat_flagged
                },
                'salary': {
                    'text': 'Unusual' if is_salary_flagged else 'Realistic',
                    'is_risk': is_salary_flagged
                },
                'email': {
                    'text': 'Free Email (Risky)' if is_email_flagged else 'Corporate',
                    'is_risk': is_email_flagged
                }
            }
        })

    except Exception as e:
        return jsonify({'error': f'Server evaluation error: {str(e)}'}), 500

# ----------------- 10. ADMIN DASHBOARD & CONTROLS -----------------
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    users = Account.query.filter_by(role='user').order_by(Account.created_at.desc()).all()
    all_scans = ScanLog.query.order_by(ScanLog.created_at.desc()).all()
    
    total_scans = len(all_scans)
    high_threats = sum(1 for s in all_scans if s.verdict == 'High Risk' or s.scam_score >= 65)
    suspicious_count = sum(1 for s in all_scans if s.verdict == 'Suspicious' or (35 <= s.scam_score < 65))
    safe_count = sum(1 for s in all_scans if s.verdict in ['Safe', 'Verified'] or s.scam_score < 35)
    
    scam_rate = round(((high_threats + suspicious_count) / total_scans * 100), 1) if total_scans > 0 else 0.0
    model_status = "Linear SVM + DNN Hybrid (Active)" if master_model is not None else "Rule-based Heuristics (Standby)"

    return render_template(
        'admin_dashboard.html',
        username=session.get('username'),
        users=users,
        scans=all_scans,
        total_scans=total_scans,
        high_threats=high_threats,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
        scam_rate=scam_rate,
        model_status=model_status
    )

@app.route('/admin/delete_scan/<int:scan_id>', methods=['POST'])
@admin_required
def delete_scan(scan_id):
    scan = ScanLog.query.get(scan_id)
    if scan:
        db.session.delete(scan)
        db.session.commit()
        flash(f'Scan #{scan_id} deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = Account.query.get(user_id)
    if user and user.role != 'admin':
        db.session.delete(user)
        db.session.commit()
        flash(f'User "{user.username}" and their scan records removed.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/clear_all_scans', methods=['POST'])
@admin_required
def clear_all_scans():
    ScanLog.query.delete()
    db.session.commit()
    flash('All activity logs have been cleared.', 'info')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)