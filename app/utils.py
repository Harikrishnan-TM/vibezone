from supabase import create_client, Client
import os
from dotenv import load_dotenv
import mimetypes
import uuid
from datetime import datetime

# Load environment variables from .env file
load_dotenv()

# Retrieve Supabase URL and Key from environment variables
url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_KEY")

# Create a Supabase client instance
supabase: Client = create_client(url, key)

def upload_file_to_supabase(file, user_id=None):
    try:
        # Ensure the file pointer is at the start
        file.seek(0)
        file_bytes = file.read()
        original_name = file.name

        # Generate a unique filename using timestamp and user_id or UUID
        ext = os.path.splitext(original_name)[-1]
        unique_id = str(user_id) if user_id else str(uuid.uuid4())
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        unique_filename = f"{timestamp}_{unique_id}{ext}"

        # Guess the content type (MIME type)
        content_type, _ = mimetypes.guess_type(original_name)
        content_type = content_type or "application/octet-stream"

        # Upload the file to Supabase storage
        response = supabase.storage.from_('kyc-files').upload(
            unique_filename,
            file_bytes,
            {"content-type": content_type}
        )

        # Handle upload errors
        if response.get("error"):
            error_msg = response["error"]["message"]
            print(f"Error uploading file: {error_msg}")
            return None

        # Retrieve and return the public URL
        file_url = supabase.storage.from_('kyc-files').get_public_url(unique_filename)
        return file_url

    except Exception as e:
        print(f"An error occurred during file upload: {e}")
        return None
