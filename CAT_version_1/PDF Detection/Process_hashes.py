import csv
# import Download_attachements

input_file = 'C:/Users/siham/PycharmProjects/CAT/PDF Detection/cleaned_file.csv'
output_file = 'C:/Users/siham/PycharmProjects/CAT/PDF Detection/Processed_hashes.csv'

# This on is for windows
# input_file = 'C:/Users/siham/PycharmProjects/CAT/PDF Detection/cleaned_file.csv'
# output_file = 'C:/Users/siham/PycharmProjects/CAT/PDF Detection/Processed_hashes.csv'

allowed_file_types = [' pdf',' doc',' docx',' ppt',' pptx',' xls',' xlsx',' xlsm',' xlsb',' xlt',' xltx',' xlam']

with open(input_file, 'r',encoding='utf-8') as in_file:
    reader = csv.DictReader(in_file)
    #print(list(reader))
    #print(type(' exe'))

    rows = [row for row in reader if row['file_type_guess'] in allowed_file_types]


with open(output_file, 'w',encoding='utf-8') as out_file:
    writer = csv.DictWriter(out_file, fieldnames=reader.fieldnames)
    writer.writeheader()
    print(reader.fieldnames)
    for row in rows:
        writer.writerow(row)