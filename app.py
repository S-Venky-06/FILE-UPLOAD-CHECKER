from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
import os
import uuid
import magic
import yara
import logging

# ---------------- CONFIG ----------------

ALLOWED_EXTENSION_MIME_MAP = {
    "pdf": ["application/pdf"],
    "jpg": ["image/jpeg"],
    "png": ["image/png"],
    "txt": ["text/plain"]
}

UPLOAD_FOLDER = "uploads"
QUARANTINE_FOLDER = "quarantine"
LOG_DIR = "logs"
LOG_FILE = "logs/security.log"

ALLOWED_EXTENSIONS = {"jpg", "png", "pdf", "txt"}
MAX_FILE_SIZE_MB = 10
YARA_RULES_PATH = "rules/malware.yar"

# ---------------- INIT ----------------

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE_MB * 1024 * 1024

yara_rules = yara.compile(filepath=YARA_RULES_PATH)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

# ---------------- HELPERS ----------------

def log_event(level, message):
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.warning(message)
    elif level == "error":
        logging.error(message)


def detect_mime_type(file_path):
    return magic.from_file(file_path, mime=True)


def is_allowed_file_type(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_unique_filename(original_filename):
    safe_filename = secure_filename(original_filename)
    return f"{uuid.uuid4()}_{safe_filename}"


def yara_scan(file_path):
    return yara_rules.match(file_path)

# ---------------- ROUTES ----------------

@app.route("/")
def home():
    return render_template("upload.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    client_ip = request.remote_addr

    # 1 File presence
    if "file" not in request.files:
        log_event("warning", f"BLOCKED | IP={client_ip} | reason=no_file_part")
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]

    if file.filename == "":
        log_event("warning", f"BLOCKED | IP={client_ip} | reason=no_filename")
        return jsonify({"error": "No selected file"}), 400

    # 2 Extension check
    if not is_allowed_file_type(file.filename):
        log_event(
            "warning",
            f"BLOCKED | IP={client_ip} | filename={file.filename} | reason=extension_not_allowed"
        )
        return jsonify({"error": "File extension not allowed"}), 400

    # 3 Save file
    unique_filename = generate_unique_filename(file.filename)
    save_path = os.path.join(UPLOAD_FOLDER, unique_filename)
    file.save(save_path)

    # 4 MIME validation
    mime_type = detect_mime_type(save_path)
    extension = unique_filename.rsplit(".", 1)[1].lower()
    allowed_mimes = ALLOWED_EXTENSION_MIME_MAP.get(extension, [])

    if mime_type not in allowed_mimes:
        os.replace(save_path, os.path.join(QUARANTINE_FOLDER, unique_filename))
        log_event(
            "warning",
            f"BLOCKED | IP={client_ip} | filename={file.filename} | "
            f"stored={unique_filename} | detected_mime={mime_type} | "
            f"expected={allowed_mimes} | reason=mime_mismatch"
        )
        return jsonify({"error": "Blocked: MIME mismatch"}), 400

    # 5 YARA scan
    yara_matches = yara_scan(save_path)
    if yara_matches:
        os.replace(save_path, os.path.join(QUARANTINE_FOLDER, unique_filename))
        rules = [match.rule for match in yara_matches]
        log_event(
            "error",
            f"BLOCKED | IP={client_ip} | filename={file.filename} | "
            f"stored={unique_filename} | yara_rules={rules}"
        )
        return jsonify({"error": "Blocked: Malware detected"}), 400

    # 6 Success
    log_event(
        "info",
        f"ALLOWED | IP={client_ip} | filename={file.filename} | "
        f"stored={unique_filename} | mime={mime_type}"
    )

    return jsonify({
        "message": "File uploaded successfully",
        "filename": unique_filename,
        "mime_type": mime_type
    }), 200


if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
