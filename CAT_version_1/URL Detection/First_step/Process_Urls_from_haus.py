from Blacklist_URL_Database import *
import time
# Here, we will try to extract just the URLs that are "online",
def extract_just_urls(input_file, output_file):
    with open(input_file) as f:
        lines = f.readlines()
    with open(output_file, "w") as f:
        for line in lines:
            #if "online" in line:
            if not line.startswith("#"):
                elements = line.split(",")
                if len(elements) > 2:
                    element = elements[2].strip().strip("\"")
                    f.write(element + "\n")
    return output_file

# input_file = 'csv.txt'
# output_file = 'output.txt'
# extract_just_urls(input_file, output_file)
# Here, we will process the extracted database, and we will extract just the urls
Black_URLS_file = 'Black_urls.txt'
Black_URLS_file=extract_just_urls(DB_Final_Path, Black_URLS_file)