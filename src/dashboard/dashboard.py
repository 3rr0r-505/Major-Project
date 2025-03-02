from flask import Flask, render_template, request, abort
from pymongo import MongoClient
from bson import ObjectId
import logging
import gridfs
import json

app = Flask(__name__)

# Configure logging
# logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client.honeypott3r
collection = db.scan_results
fs = gridfs.GridFS(db)  # GridFS for fetching complete reports

@app.route("/")
def index():
    """Renders the homepage with a list of scan results."""
    try:
        data = list(collection.find({}, {"_id": 1, "name": 1, "Date&Time": 1, "used creds.ipv4": 1, "used creds.port": 1}))
    except Exception as e:
        logging.error(f"Error fetching scan results: {e}")
        abort(500, "Internal Server Error")
    
    return render_template("index.html", data=data)

@app.route("/dashboard")
def dashboard():
    test_id = request.args.get("id")

    if not test_id:
        return "Missing test identifier", 400

    try:
        result = collection.find_one({"_id": ObjectId(test_id)})
        if not result:
            return "Test not found", 404
    except Exception as e:
        logging.error(f"Invalid test_id format: {test_id} - Error: {e}")
        return "Invalid test identifier", 400

    reports = result.get("scans", {})  # Ensure it returns an empty dict instead of None

    return render_template("dashboard.html", reports=reports, test_id=test_id)

@app.route("/report")
def report():
    report_type = request.args.get("type")  # Get report type
    test_id = request.args.get("id")  # Get test ID

    if not report_type or not test_id:
        return "Invalid request", 400

    try:
        result = collection.find_one({"_id": ObjectId(test_id)})
        if not result:
            return "No reports found for this test", 404
    except Exception:
        return "Invalid test identifier", 400

    # Handle individual scan reports
    if report_type in ["nmap_scan", "nikto_scan", "WPscan_scan", "msf_scan"]:
        report_content = result.get("scans", {}).get(report_type, "No data available")

    # Handle attack module reports
    elif report_type in ["honeypot_detection", "code_injection", "data_leakage", "evading_logs", "privilege_escalation", "dos_attack"]:
        report_content = result.get("attacks", {}).get(report_type, "No data available")

    # Handle reverse exploitation (nested fields)
    elif report_type in ["Static Analysis", "Package Analysis"]:
        report_content = result.get("attacks", {}).get("reverse_exploitation", {}).get(report_type, "No data available")

    # Handle full attack module report when clicking "Attack Modules"
    elif report_type == "attacks":
        report_content = result.get("attacks", "No attack data available")

    # Handle complete report
    elif report_type == "complete":
        file_id = str(result.get("log_file_id")) # Extract ObjectId string

        if not file_id:
            return "Log file not found", 404

        try:
            log_file = fs.get(ObjectId(file_id))  # Fetch file from GridFS
            log_content = log_file.read().decode("utf-8")  # Read & decode content
            return render_template("report.html", module_name="Complete Report", report_content=log_content, test_id=test_id)
        except Exception as e:
            logging.error(f"Error fetching logfile from GridFS: {e}")
            return "Error retrieving log file", 500

    else:
        return "Invalid report type", 400

    return render_template("report.html", module_name=report_type, report_content=report_content, test_id=test_id)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)  # Change to True only in development
