# The following script is for checking the local database, to detect existing malicious files

import hashlib
import csv

def check_shared_document(shared_document):
    doc_info = dict()
    with open(shared_document, 'rb') as f:
        file_bytes = f.read()
        md5_hash = hashlib.md5(file_bytes).hexdigest()
        with open('C:/Users/siham/PycharmProjects/CAT/PDF Detection/processed_hashes.csv', 'r',encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if (row['md5_hash']).strip() == md5_hash:
                    doc_info['status'] = '1'
                    doc_info['result'] = 'malicious'
                    doc_info['file_name'] = row['file_name']
                    doc_info['file_type'] = row['file_type_guess']
                    doc_info['first_seen'] = row['# "first_seen_utc"']
                    print(md5_hash)
                    return(doc_info)

            doc_info['status'] = '0'
            doc_info['result'] = 'clean'
            print(md5_hash)
            return(doc_info)

print(check_shared_document('C:/Users/siham/PycharmProjects/CAT/PDF Detection/hi.doc'))