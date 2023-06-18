import requests
import zipfile
import io
import csv

download_url="https://bazaar.abuse.ch/export/csv/full/"
# extract_dir = "C:/Users/siham/PycharmProjects/CAT/PDF Detection" # This one for windows
extract_dir = "C:/Users/siham/PycharmProjects/CAT/PDF Detection"

# Here, we download and decompress our database
def attachements_hash_download(Download_API, extract_dir):

    response = requests.get(Download_API)
    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
        zip_file.extractall(extract_dir)

    # URLs_FinalFile_Path = "C:/Users/siham/PycharmProjects/CAT/PDF Detection/" + (zip_file.namelist())[0]
    URLs_FinalFile_Path = "C:/Users/siham/PycharmProjects/CAT/PDF Detection/" + (zip_file.namelist())[0]
    # The following is the path(name) of the extracted file :
    return (URLs_FinalFile_Path)

doc_hash_file_path = attachements_hash_download(download_url,extract_dir)

# Here, we delete the  first 8 lines from the database , because they contain just the description of the database
with open(doc_hash_file_path, 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    rows = list(reader)
    # print(rows)

    del rows[:8]
    del rows[-1]
    print('yes')

# new_file='C:/Users/siham/PycharmProjects/CAT/PDF Detection/updated.csv'
new_file='C:/Users/siham/PycharmProjects/CAT/PDF Detection/updated.csv'

with open(new_file, 'w', newline='',encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerows(rows)

doc_hash_file_path0 = new_file
# Here, we clean our database (it contains quotes nad spaces etc)
with open(doc_hash_file_path0, 'r',encoding='utf-8') as infile, open('cleaned_file.csv', 'w', newline='',encoding='utf-8') as outfile:
    reader = csv.reader(infile)
    writer = csv.writer(outfile)
    headers = next(reader)
    writer.writerow(headers)
    for row in reader:
        cleaned_row = [field.replace('"','') for field in row]
        writer.writerow(cleaned_row)
