

from supabase import create_client, Client
import os
from dotenv import load_dotenv



# Load environment variables from .env file
load_dotenv()

# Retrieve Supabase URL and Key from environment variables
url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_KEY")



# Create a Supabase client instance
supabase: Client = create_client(url, key)

def upload_file_to_supabase(file):
    try:
        # Upload the file to Supabase Storage
        response = supabase.storage.from_('kyc-files').upload(file.name, file)

        if response.status_code == 200:  # Check if the upload was successful
            # Get the public URL of the uploaded file
            file_url = supabase.storage.from_('kyc-files').get_public_url(file.name)
            return file_url
        else:
            # Handle errors if the file upload fails
            print(f"Error uploading file: {response.status_code}, {response.text}")
            return None

    except Exception as e:
        print(f"An error occurred during file upload: {e}")
        return None
