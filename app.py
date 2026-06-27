import os
import re
import sqlite3
from flask import Flask, render_template, request, jsonify

# Initialize Flask application.
# The folder structure expects:
#   ├── app.py
#   └── templates/
#       ├── index.html
#       ├── education.html
#       ├── quiz.html
#       └── reporting.html
app = Flask(__name__, template_folder='templates')

DATABASE_NAME = 'cyberguard.db'

def get_db_connection():
    """
    Establishes and returns a connection to the SQLite database.
    Configures the connection to return rows as dictionaries for easier access.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row  # Enables column access by name
    return conn

def init_db():
    """
    Initializes the SQLite database.
    1. Creates the 'scam_reports' table if it does not already exist.
    2. Pre-seeds the table with sample reports to ensure search can be demonstrated instantly.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create the scam_reports table
    # Fields:
    # - id: Auto-incrementing unique identifier
    # - phone_number: The reported fraudulent phone number
    # - company_name: The brand name the fraudster was impersonating
    # - description: Detailed explanation of the scam mechanics
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT NOT NULL,
            company_name TEXT NOT NULL,
            description TEXT NOT NULL
        )
    ''')
    
    # Check if we already have data. If not, insert sample rows.
    cursor.execute('SELECT COUNT(*) FROM scam_reports')
    count = cursor.fetchone()[0]
    
    if count == 0:
        # Pre-seeding 2 target scam numbers:
        # Number 1: "9876543210" - Will have 2 reports (High Risk scenario)
        # Number 2: "8889991111" - Will have 1 report (Suspicious scenario)
        sample_reports = [
            ("9876543210", "Paytm Security Support", "Fake operator claiming Paytm Wallet suspension. Demanded OTP and UPI PIN to restore access."),
            ("9876543210", "Paytm KYC Team", "Scammer called posing as a verification officer and requested installation of AnyDesk App."),
            ("8889991111", "Amazon Refund Helpdesk", "Sent a phishing SMS offering a product refund of ₹10,000. Asked to scan a QR code.")
        ]
        
        cursor.executemany(
            'INSERT INTO scam_reports (phone_number, company_name, description) VALUES (?, ?, ?)',
            sample_reports
        )
        conn.commit()
        print("[DATABASE] Pre-seeded 3 sample records successfully.")
        
    conn.close()

# ------------------------------------------
# FRONTEND TEMPLATE ROUTES
# ------------------------------------------

@app.route('/')
def index():
    """Renders the main verification checker dashboard."""
    return render_template('index.html')

@app.route('/education')
def education():
    """Renders the official support directory and awareness hub."""
    return render_template('education.html')

@app.route('/quiz')
def quiz():
    """Renders the interactive cybersecurity safety test."""
    return render_template('quiz.html')

@app.route('/reporting')
def reporting():
    """Renders the community threat registration form."""
    return render_template('reporting.html')

# ------------------------------------------
# CORE BACKEND REST API ENDPOINTS
# ------------------------------------------

def sanitize_number(num_str):
    """
    Helper utility to sanitize search queries.
    Removes spaces, hyphens, and country code prefixes (+91 or 91)
    to match the base 10-digit format stored in our records.
    """
    if not num_str:
        return ""
    # Strip any non-digit character (e.g. spaces, brackets, + signs, dashes)
    digits_only = re.sub(r'\D', '', num_str)
    
    # If it is a 12-digit Indian number starting with 91, strip the 91
    if len(digits_only) == 12 and digits_only.startswith('91'):
        return digits_only[2:]
    return digits_only

@app.route('/check-number', methods=['POST'])
def check_number():
    """
    Verification API:
    Analyzes an incoming phone number using a strict verification hierarchy:
    1. Verified corporate whitelist check (Green)
    2. Database blacklist check (Red)
    3. Unverified mobile check (Orange)
    4. Fallback safe check (Green)
    """
    # Accept both JSON (from JS Fetch API) and standard Form data
    data = request.get_json() if request.is_json else request.form
    
    raw_number = data.get('phone_number', '').strip()
    sanitized = sanitize_number(raw_number)
    
    if not sanitized:
        return jsonify({
            'status': 'error',
            'message': 'Please provide a valid phone number to check.'
        }), 400

    # 1. Verified Corporate Whitelist (Dictionary mapping numbers to names)
    verified_corporate_whitelist = {
        "18001234": "SBI Support",
        "18004190157": "Axis Bank",
        "18002662255": "HDFC Bank"
    }

    if sanitized in verified_corporate_whitelist:
        company_name = verified_corporate_whitelist[sanitized]
        return jsonify({
            'status': '✅ VERIFIED GENUINE COMPANY',
            'color': '#16a34a',
            'phone_number': raw_number,
            'sanitized_number': sanitized,
            'report_count': 0,
            'risk_level': 'VERIFIED GENUINE COMPANY',
            'verdict': f'Success: This is the official verified helpline contact of {company_name}. It is 100% safe to initiate communications with this endpoint.',
            'reports': []
        })

    # Query database for matching scam reports
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT company_name, description FROM scam_reports WHERE phone_number = ?', 
        (sanitized,)
    )
    matching_rows = cursor.fetchall()
    conn.close()
    
    reports_list = []
    for r in matching_rows:
        reports_list.append({
            'company_name': r['company_name'],
            'description': r['description']
        })
        
    report_count = len(reports_list)
    
    # 2. Database Blacklist Check
    if report_count >= 1:
        return jsonify({
            'status': '🚨 CONFIRMED FAKE SCAMMER',
            'color': '#dc2626',
            'phone_number': raw_number,
            'sanitized_number': sanitized,
            'report_count': report_count,
            'risk_level': 'CONFIRMED FAKE SCAMMER',
            'verdict': f'Danger: This number is blacklisted in our database with {report_count} active threat reports. Do not share OTPs, do not install remote apps, and do not transfer funds (₹).',
            'reports': reports_list
        })

    # 3. Regex check for standard 10-digit Indian mobile number format (starting with 6-9)
    is_mobile_format = re.match(r'^[6-9]\d{9}$', sanitized)
    if is_mobile_format:
        return jsonify({
            'status': '⚠️ UNVERIFIED MOBILE ENDPOINT',
            'color': '#f97316',
            'phone_number': raw_number,
            'sanitized_number': sanitized,
            'report_count': 0,
            'risk_level': '⚠️ UNVERIFIED MOBILE ENDPOINT',
            'verdict': 'No active user complaints found, but this is a private personal mobile line. Official corporate supports use designated toll-free or landline systems.',
            'reports': []
        })

    # 4. Fallback Safe Check
    return jsonify({
        'status': 'safe',
        'color': '#16a34a',
        'phone_number': raw_number,
        'sanitized_number': sanitized,
        'report_count': 0,
        'risk_level': 'SAFE / NO RECORDS FOUND',
        'verdict': 'No active warnings or threat intelligence reports are logged against this contact. Always verify credentials independently before sharing banking parameters (₹).',
        'reports': []
    })

@app.route('/submit-report', methods=['POST'])
def submit_report():
    """
    Reporting API:
    Allows community users to register newly identified scam numbers.
    Validates the input formats, inserts into SQLite, and returns success confirmation.
    """
    data = request.get_json() if request.is_json else request.form
    
    raw_number = data.get('phone_number', '').strip()
    company_name = data.get('company_name', '').strip()
    description = data.get('description', '').strip()
    
    sanitized_number = sanitize_number(raw_number)
    
    # Basic validation
    if not sanitized_number or len(sanitized_number) < 5:
        return jsonify({
            'status': 'error',
            'message': 'Please provide a valid, complete phone number (at least 5 digits).'
        }), 400
        
    if not company_name:
        return jsonify({
            'status': 'error',
            'message': 'Company name or impersonated entity is required.'
        }), 400
        
    if not description or len(description) < 10:
        return jsonify({
            'status': 'error',
            'message': 'Please write a descriptive report of at least 10 characters to assist others.'
        }), 400
        
    # Write to database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO scam_reports (phone_number, company_name, description) VALUES (?, ?, ?)',
        (sanitized_number, company_name, description)
    )
    conn.commit()
    conn.close()
    
    return jsonify({
        'status': 'success',
        'message': f'Threat registered successfully. Thank you for securing our community!'
    })

# Initialize DB when running local server
init_db()

if __name__ == '__main__':
    # Run the server on port 5000 during local Python execution
    print("[SERVER] Launching CyberGuard portal on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
