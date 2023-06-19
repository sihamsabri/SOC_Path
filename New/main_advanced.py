from Extract_links import *
sys.path.insert(0,'C:/Users/siham/PycharmProjects/CAT/URL Detection/First_step')
sys.path.insert(0,'C:/Users/siham/PycharmProjects/CAT/PDF Detection/')

from check_Documents_DB import *
from similarity_testing import *
from First_check import *

def advanced_url_analysis(list):

    print("This function takes a list of extracted urls from a message text,")
    print("for each url, it checks weither it is a directly download, if so, it checks the local database")
    print("Sinon, it extract different displayed links in its webpages and check them")
    print("The result is a list")

    url_advanced_result_Download = []
    url_advanced_result_link = []
    iframe_src = []

    for url in list:
        try:
            response = requests.get(url)
            if response.status_code == 200:
                if check_downloadable_url(url):
                    downloaded_file_path = downloadFile_fromUrl(url)
            # Print(type(check_shared_document(downloaded_file_path)))
                    url_advanced_result_Download.append(check_shared_document(downloaded_file_path))
                    print(check_shared_document(downloaded_file_path))
                else:
            # This part is for embedded link in the webpage!
                    print("Lets check the embbeded link in each url")
                    iframe = check_iframe_src(url)
                    # print(iframe)
                    if iframe is not None :
                        if iframe[0] == 1 or iframe[1] == 1:
                            return(1)
                    print("lets check other links that we may find in the webpage!")
                    extracted_links=extracted_links_analysis(url)
                    if extracted_links is not None:
                        if extracted_links[0] == 1 or extracted_links[1] == 1:
                            return(1)
            else:
                print(url + " is not accessible!")

        except requests.exceptions.ConnectionError:
            print(url+" is not accessible!")
            continue
    return(0)

# print(advanced_url_analysis(['https://github.com/vector-im/matrix-content-scanner-python/blob/main/docs/api.md']))
# print(advanced_url_analysis(['https://bazaar.abuse.ch/export/csv/full/','https://www.wikihow.com/Make-a-File-Downloadable-from-Your-Website']))