from similarity_testing import *
from Process_Urls_from_haus import *
from ip_reputation import *

def url_first_check(List_of_extracted_urls):

    # This line is for calculating the ip reputation of the extracted URLs;
    ip_reputation_result = ip_reputation(List_of_extracted_urls)

    # Here, we will calculate the similarity between the extracted urls and the blacklisted urls;
    levenshtein_scores = calculate_similarity(Black_URLS_file, List_of_extracted_urls)

    # We've chosen 0.65 as a threshold value to detect similarity;
    threshold = 0.65

    # We return a list containing the final result of the similarity calculation;
    final_result = url_result(levenshtein_scores, threshold)

    if any(final_result):

        DB_result = 1
    else:

        DB_result = 0

    print("Extracted urls from the text: \n", List_of_extracted_urls, sep="")

    # print("Final Result Lists: \n Database Check, ip-Reputation, Domain-Name-Reputation")
    # print(final_result, ip_reputation_list)
    # Finally, We return :

    return (ip_reputation_result,DB_result)