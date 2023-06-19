import sys
import requests
import os
import re

sys.path.insert(0,'C:/Users/siham/PycharmProjects/CAT/URL Detection/First_step')
sys.path.insert(0,'C:/Users/siham/PycharmProjects/CAT/PDF Detection/')

from First_check import *
import check_Documents_DB
from bs4 import BeautifulSoup

# Our algorithm:
# First case: Check, weither the url is actually a direct download of a file, in this case,
# We download this file on a sandbox, and then calculate its hash to see if it is malicious or not.

def check_downloadable_url(url):
    response = requests.head(url)
    # Check if the Content-Disposition header is present.
    if 'Content-Disposition' in response.headers:
        print(f"{url} is directly downloadable.1")
        return True

    else:
        # Check if the Content-Type header indicates a downloadable file
        content_type = response.headers.get('Content-Type')
        if content_type and content_type.startswith(('application/', 'image/', 'audio/', 'video/')):
            print(f"{url} is directly downloadable.2")
            return True

        else:
            print(f"{url} is not directly downloadable.")
            return False
# Test
url = "https://bazaar.abuse.ch/export/csv/full/"
# check_downloadable_url(url)

def downloadFile_fromUrl(url):

    filename = "Downloaded_file"
    response = requests.get(url)
    with open(filename, "wb") as f:
        f.write(response.content)
    print(f"{filename} has been downloaded.")
    # Here, we return the absolute path of the downloaded file to check its hash in the local database.
    return(os.path.abspath(filename))

url = "https://bazaar.abuse.ch/export/csv/full/"

# Downloaded_file_path=downloadFile_fromUrl(url)
# print(Downloaded_file_path)
# print(check_Documents_DB.check_shared_document(Downloaded_file_path))
# Second case: if it is a webpage, we try to extract all the available links on this page,
# and check them using the local database
# This function is for extracting different links from a given url

def extract_link_fromUrl(url):

    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    links = []
    final_links = []
    for link in soup.find_all("a"):
        href = link.get("href")
        if href and not href.startswith("#"):
            links.append(href)
    # The list may contain some other elements different from urls
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

    # url_pattern = re.compile(r'(https?://)?(www\.)?[a-zA-Z0-9]+\.[a-zA-Z]+(/[^\s]*)?')
    for elm in links:
        matches = re.findall(url_pattern, elm)
        final_links.extend(matches)
    # print(links)
    #print(final_links)
    return(final_links)

# This function analyses the extracted links!
def extracted_links_analysis(url):
    result=dict()
    result['id']='extracted links from the url'
    extracted_links=extract_link_fromUrl(url)
    #print(extracted_links)
    if extracted_links!=[]:
        L= url_first_check(extracted_links)
        return(L)
# print(extracted_links_analysis('https://linuxconfig.org/kali-http-server-setup'))

# This function is for extracting iframe sources
def iframe_analysis(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    iframe_tags = soup.find_all('iframe')
    iframe_src_list = []
    final_ifrm_src_list=[]
    for iframe in iframe_tags:
        src = iframe.get('src')
        iframe_src_list.append(src)
    # On check, si ils sont des liens!
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    for elm in iframe_src_list:
        matches = re.findall(url_pattern, elm)
        final_ifrm_src_list.extend(matches)
    return final_ifrm_src_list

url = 'http://10.224.138.156:9000/'
# iframe_analysis(url)

def check_iframe_src(url):
    result = dict()
    result['id']='iframe sources'
    iframe_src=iframe_analysis(url)
    if  iframe_src!= []:
        print(iframe_analysis(url))
        L = url_first_check(iframe_src)
        return(L)

# print(check_iframe_src(url))

# Test
# url = "https://aliatalay.net/isletme/2016iibfex.doc"
# extracted_links_from_url = extract_links_from_url(url)
# Calculate the reputation & check the url in virus total
# print(ip_reputation(extracted_links_from_url))
# print()