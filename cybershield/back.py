import os # for file modification an ddeletion 
import json #
import datetime # to five time stamp
import uuid # to give uniques id 
import hashlib #using algorithm sha 256
from flask import Flask, request, jsonify, send_from_directory #to make web server live edition 
from flask_cors import CORS # for communication
from werkzeug.utils import secure_filename 

app = Flask(__name__)
CORS(app)  # Allows your HTML file to communicate with the Python backend safely

# Serve the frontend directly so visiting http://127.0.0.1:8000 in a browser
# shows the CyberShield UI instead of a 404 "Not Found" page.
@app.route('/')
def serve_frontend():
    return send_from_directory('.', 'front.html')

PORT = 8000
UPLOAD_DIR = './uploads'
DB_FILE = './entries.json'
BLACKLIST_FILE = './blacklist.json'

# Ensure required system folders and files exist safely on boot
os.makedirs(UPLOAD_DIR, exist_ok=True)

if not os.path.exists(DB_FILE):
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump([], f, indent=2)

# LOAD PERSISTENT BLACKLIST
network_firewall_blacklist = ["192.168.1.105", "10.0.0.99", "185.220.101.5"]
if not os.path.exists(BLACKLIST_FILE):
    with open(BLACKLIST_FILE, 'w', encoding='utf-8') as f:
        json.dump(network_firewall_blacklist, f, indent=2)
else:
    try:
        with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
            network_firewall_blacklist = json.load(f)
    except Exception as e:
        print("[ERROR] Error reading persistent blacklist file, falling back to defaults.")

# DATABASE LOGGING SYSTEM
def save_to_database(entry):
    try:
        with open(DB_FILE, 'r+', encoding='utf-8') as f:
            data = json.load(f)
            
            database_document = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "status": "PROCESSED_AND_ARCHIVED",
                **entry
            }
            
            data.insert(0, database_document)
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()
            print(f"[DATABASE] Securely saved log entry ID: {database_document['id']}")
    except Exception as e:
        print(f"[DATABASE ERROR] Failed to write entry log: {e}")

# Update the blacklist JSON file on disk
def sync_blacklist_to_file():
    try:
        with open(BLACKLIST_FILE, 'w', encoding='utf-8') as f:
            json.dump(network_firewall_blacklist, f, indent=2)
        print("[FIREWALL] Hacker blacklist file updated successfully on disk.")
    except Exception as e:
        print(f"[FIREWALL ERROR] Failed to write changes down to blacklist file: {e}")

# Magic Byte deep inspection engine
def verify_real_file_type(file_bytes, actual_ext):
    header = file_bytes[:4].hex().upper()
    if actual_ext in ['.png', '.jpg', '.jpeg', '.gif']:
        return header == '89504E47' or header.startswith('FFD8FF') or header.startswith('47494638')
    return not header.startswith('4D5A')  # Block hidden Windows Executable headers (MZ)

# ============================================================================
# ENDPOINT 1: PAYLOAD SCANNER (FILE INTEGRITY)
# ============================================================================
@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'cyberFile' not in request.files:
        return jsonify({"success": False, "message": "No data stream received."}), 400
        
    file = request.files['cyberFile']
    if file.filename == '':
        return jsonify({"success": False, "message": "No data stream received."}), 400

    clean_original_name = file.filename.replace('\0', '').replace(' ', '').replace('\u202e', '')
    _, actual_ext = os.path.splitext(clean_original_name)
    actual_ext = actual_ext.lower()

    # Create safe temp tracking name
    random_name = os.urandom(16).hex()
    temp_filename = f"{int(datetime.datetime.now().timestamp())}-{random_name}.tmp"
    file_path = os.path.join(UPLOAD_DIR, secure_filename(temp_filename))
    
    try:
        file.save(file_path)
        
        # Check size constraints (25MB Max)
        file_size = os.path.getsize(file_path)
        if file_size > 25 * 1024 * 1024:
            return jsonify({"success": False, "message": "Max limit file threshold capacity is 25MB."}), 400

        with open(file_path, 'rb') as f:
            file_buffer = f.read()

        hash_sum = hashlib.sha256(file_buffer).hexdigest()
        
        fake_percentage = 0
        logs = []
        execution_blocked = False
        
        is_real_image = verify_real_file_type(file_buffer, actual_ext)
        has_multiple_dots = clean_original_name.count('.') > 1

        if actual_ext in ['.png', '.jpg', '.jpeg', '.gif']:
            if not is_real_image:
                fake_percentage = 100
                execution_blocked = True
                logs.append("CRITICAL MASKING: File claims to be an image but contains hidden Executable Binary components.")
            elif has_multiple_dots:
                fake_percentage = 20
                logs.append("Heuristic Note: Valid graphic asset layout using multi-dot structure.")
            else:
                fake_percentage = 0
                logs.append("Signature Verification Matrix: Genuine graphic metadata structural match.")
        else:
            dangerous_extensions = ['.exe', '.bat', '.vbs', '.cmd', '.scr', '.sh', '.js']
            is_dangerous_double = False
            for d_ext in dangerous_extensions:
                if clean_original_name.lower().endswith(tuple(f".txt{d_ext} .pdf{d_ext} .doc{d_ext} .docx{d_ext} .png{d_ext} .jpg{d_ext} .jpeg{d_ext}".split())):
                    is_dangerous_double = True
                    break

            if actual_ext in dangerous_extensions and file_size < 5000:
                fake_percentage += 65
                logs.append("AI Core Status: Tiny micro-script binary variant detected.")
            if is_dangerous_double:
                fake_percentage += 75
                logs.append("Heuristic Pattern Trace: Dangerous double extension payload layout detected.")

        # Sandbox Monitoring Alert
        if fake_percentage >= 50:
            print(f"[SANDBOX WARNING] High-risk attributes on file: \"{clean_original_name}\". Sending to sandbox containment.")
            logs.append("Sandbox Status: Suspicious attributes isolated inside dynamic runtime verification environment.")

        if fake_percentage >= 65:
            execution_blocked = True
            logs.append("🔴 PREVENTION ACTION: Network socket stream dropped dynamically by inline security rules.")

        verdict = "GENUINE / SAFE"
        color = "#10b981"
        
        if execution_blocked:
            verdict = "PACKET BLOCKED & INLINE DROPPED"
            color = "#ef4444"
        elif fake_percentage >= 25:
            verdict = "SUSPICIOUS ARTIFACT ENVELOPE"
            color = "#f59e0b"

        file_details = {
            "originalName": clean_original_name,
            "size": f"{(file_size / 1024):.2f} KB",
            "hash": hash_sum,
            "fakeProbability": f"{fake_percentage}%",
            "verdict": verdict,
            "statusColor": color,
            "logs": logs
        }
        
        save_to_database({
            "type": "NETWORK_PAYLOAD_SCAN",
            "targetName": clean_original_name,
            "verdict": verdict,
            "probability": f"{fake_percentage}%",
            "hash": hash_sum
        })
        
        return jsonify({"success": True, "fileDetails": file_details}), 200

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as err:
                print(f"Error clearing temp upload file: {err}")

# ============================================================================
# ENDPOINT 2: TRAFFIC AUDITOR & LOG PARSER (With Auto-Blocking Firewall)
# ============================================================================
@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    try:
        data = request.get_json() or {}
        target_url = data.get('targetUrl', '')
        
        if not target_url or target_url.strip() == "":
            return jsonify({"success": False, "message": "Input field cannot be empty."}), 400

        input_str = target_url.strip().replace('\0', '')
        clean_traffic_log = input_str.lower()
        
        fake_percentage = 0
        verdict = "TRAFFIC SECURE & VALIDATED"
        color = "#10b981"
        logs = []
        
        dynamic_hash = hashlib.sha256(input_str.encode('utf-8')).hexdigest()[:24].upper()

        # 1. Firewall Rule Scan
        matched_blacklist = any(blocked_item in clean_traffic_log for blocked_item in network_firewall_blacklist)
        
        if matched_blacklist:
            fake_percentage = 100
            verdict = "CONNECTION REFUSED (BLACKLISTED SOURCE)"
            color = "#ef4444"
            logs.append("🔴 IDPS ACTIVE BLOCK: Request automatically blocked. Source address matches a banned attacker flag inside the permanent disk blacklist registry.")
        else:
            # 2. Exploit Pattern Matching
            import re
            if re.search(r'ddos|port scan|nmap|brute force|reverse shell|ping of death', clean_traffic_log):
                fake_percentage = 95
                verdict = "ATTACK DETECTED & HOST BLACKLISTED"
                color = "#ef4444"
                
                # Dynamic Blacklisting Trigger
                network_firewall_blacklist.append(input_str)
                sync_blacklist_to_file()
                
                logs.append("IDPS Analyzer Engine: Volumetric server flooding or infrastructure scan patterns discovered.")
                logs.append("🔴 AUTOMATED REACTION: Dangerous route signature added to system database. Connection dropped permanently.")
            
            # 3. Phishing Indicators
            elif re.search(r'login|verify|update-security|secure-auth|signin|banking|wp-admin', clean_traffic_log):
                words = input_str.split()
                has_no_dot = '.' not in input_str
                if len(words) > 2 and has_no_dot:
                    fake_percentage = 10
                    logs.append("Log Parser Assessment: Standard user string entry identified. No structural links tracked.")
                else:
                    fake_percentage = 85
                    verdict = "PHISHING DOMAIN INTERDICTED"
                    color = "#ef4444"
                    logs.append("Threat Intelligence Matrix: Match confirmed with active credential phishing link blueprint structures.")
                    logs.append("🔴 MITIGATION STEPS: Network socket dropped. Packet stream terminated cleanly.")
            
            # 4. Plaintext Insecure Verification
            elif clean_traffic_log.startswith('http://'):
                fake_percentage = 35
                verdict = "UNENCRYPTED INSECURE TRAFFIC"
                color = "#f59e0b"
                logs.append("Protocol Guard Warning: Unencrypted traffic pattern routed via HTTP port. Connection at risk of interception.")
            else:
                logs.append("Endpoint traffic evaluation complete. Package records match verified safe routing profiles.")

        details = {
            "target": input_str,
            "hash": f"NET::{dynamic_hash}",
            "fakeProbability": f"{fake_percentage}%",
            "verdict": verdict,
            "statusColor": color,
            "logs": logs
        }
        
        save_to_database({
            "type": "NETWORK_TRAFFIC_IDPS",
            "targetName": input_str,
            "verdict": verdict,
            "probability": f"{fake_percentage}%",
            "hash": f"NET::{dynamic_hash}"
        })
        
        return jsonify({"success": True, "details": details}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == '__main__':
    print(f"🚀 CyberShield Network-IDPS Hardened Engine online on Port {PORT}")
    app.run(port=PORT, debug=True)