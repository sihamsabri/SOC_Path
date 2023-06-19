import requests
import zipfile
import io

# class Blacklist_URL_Database :
Download_API = ""
URLs_DownloadedFile = ""
URLs_FinalFile_Path = ""

def urls_file_download(Download_API, extract_dir):

    # Download the ZIP file
    response = requests.get(Download_API)
    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file :
        # Extract the contents of the ZIP file
        zip_file.extractall(extract_dir)

    # print((zip_file.namelist())[0])
    URLs_FinalFile_Path = "/home/remnux/Downloads/CAT/URL Detection/First_step/" + (zip_file.namelist())[0]

    # The following is the path(name) of the extracted file :
    return(URLs_FinalFile_Path)

# This is just for test

# Download_API = "https://urlhaus.abuse.ch/downloads/csv/"

# extract_dir = "C:/Users/siham/PycharmProjects/CAT"

# urls_file_download(Download_API,extract_dir)

# This is the API from which we ere going to download our database #
Download_API = "https://urlhaus.abuse.ch/downloads/csv/"

# Here the directory path #
extract_dir = "/home/remnux/Downloads/CAT/URL Detection/First_step/"

# Here we took the final path of the database #
DB_Final_Path = urls_file_download(Download_API, extract_dir)
