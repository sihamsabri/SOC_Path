from extract_url_from_text import *
from similarity_testing import *
from Process_Urls_from_haus import *
from Receive_txt_from_henceApp import *
from ip_reputation import *

# import sys
# import schedule
# import time

def process_txt_from_HcApp(Text_message):
    #Text_message = receive()
    List_of_extracted_urls = Find_urls_from_text(Text_message)
    print(List_of_extracted_urls)


    # This one in case the message contains urls.

    if List_of_extracted_urls != 0:
        # This line is for calculating the ip reputation of the extracted URLs
        ip_reputation_list = ip_reputation(List_of_extracted_urls)
        # Here, we will calculate the similarity between the extracted urls and the blacklisted urls
        levenshtein_scores = calculate_similarity(Black_URLS_file,List_of_extracted_urls)

        # We've chosen 0.65 as a threshold value to detect similarity
        threshold = 0.65

        # We return a list containing the final result of the similarity calculation
        final_result = url_result(levenshtein_scores,threshold)

        print("Final Result Lists: Database Check, ip-Reputation, Domain-Name-Reputation")


    # Finally, we return the final result
        return(final_result, ip_reputation_list)

    # if there is no link in the message, we return 0.
    else:
        print("No urls available in this message!")
        return(0)

Text_message = sys.argv[1]
# print("Hi")
print(process_txt_from_HcApp(Text_message))
# print("Hello word!")