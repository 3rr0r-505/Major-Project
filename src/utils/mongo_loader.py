import os
import pymongo
import gridfs
from dotenv import load_dotenv
from bson import ObjectId

# Load environment variables
# load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '../configs/.env'))

class mongoLoader:
    def __init__(self):
        """Initialize MongoDB connection and GridFS."""
        # mongo_uri = os.getenv('MONGO_URI')  # For remote server
        mongo_uri = "mongodb://localhost:27017/"
        if not mongo_uri:
            raise ValueError("[!] MONGO_URI is not set.")

        self.db_name = "honeypott3r"
        self.collection_name = "scan_results"

        try:
            # Set up MongoDB client
            self.client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            self.client.admin.command('ping')  # Check connection
            self.db = self.client[self.db_name]
            self.collection = self.db[self.collection_name]
            self.fs = gridfs.GridFS(self.db)  # Initialize GridFS
        except Exception as e:
            raise ConnectionError(f"[!] Error connecting to MongoDB: {e}")

    def upload(self, report_data: dict, log_file: str):
        """
        Uploads the report data and its associated log file in a single MongoDB document.
        
        Args:
            report_data (dict): The structured report data.
            log_file (str): The name of the log file to upload (from /src/logs/).
        """
        try:
            log_path = os.path.join(os.path.dirname(__file__), '../logs', log_file)
            
            if not os.path.exists(log_path):
                raise FileNotFoundError(f"Log file not found: {log_path}")

            # Upload log file to GridFS
            with open(log_path, "rb") as file_data:
                log_file_id = self.fs.put(file_data, filename=log_file)

            # Attach the log file ID to the report data
            report_data["log_file_id"] = log_file_id  

            # Insert report with log file reference into scan_results
            result = self.collection.insert_one(report_data)
            print(f"\n[+] Report and log file uploaded successfully! Log ID: {log_file_id}, Document ID: {result.inserted_id}")

        except Exception as e:
            print(f"[!] Error uploading report and log file: {e}")

    def get_logfile(self, log_file_id, output_path=None):
        """
        Retrieves the log file from GridFS using the log_file_id.
        
        Args:
            log_file_id (str or ObjectId): The GridFS file ID to fetch.
            output_path (str, optional): Path to save the file. If None, returns the file content.
        
        Returns:
            str: File content as a string if output_path is None, else saves the file.
        """
        try:
            # Ensure log_file_id is an ObjectId
            log_file_id = ObjectId(log_file_id) if isinstance(log_file_id, str) else log_file_id

            # Fetch the file from GridFS
            log_file = self.fs.get(log_file_id)
            
            if output_path:
                with open(output_path, "wb") as f:
                    f.write(log_file.read())
                print(f"[+] Log file saved to: {output_path}")
            else:
                return log_file.read().decode("utf-8")  # Return as string if no path is given

        except gridfs.errors.NoFile:
            print(f"[!] No file found with ID: {log_file_id}")
        except Exception as e:
            print(f"[!] Error retrieving log file: {e}")
            return None
