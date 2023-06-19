from extract_url_from_text import *
from similarity_testing import *
from Process_Urls_from_haus import *
from Receive_txt_from_henceApp import *
from ip_reputation import *
import sys

# These ones, are for advanced analysis
sys.path.insert(0,'/home/remnux/Downloads/CAT/URL Detection/Second Step')
sys.path.insert(0,'/home/remnux/Downloads/CAT/PDF Detection/')
from main_advanced import *
from First_check import *

def process_txt_from_HcApp(Text_message):
    #Text_message = receive()
    List_of_extracted_urls = Find_urls_from_text(Text_message)
    return(List_of_extracted_urls)

def goto_url_advanced_analysis(result):
    goto = False
    if result[0] == 0:
        if result[1]==0:
            goto = True
            print("everything is clean")
        else:
            goto = False
            print(" Good reputation, but found on the database")
    else:
        print("Bad reputation")
        goto = True
    return goto

def url_analysis(Text_message):

    final_result=dict()
    List_of_extracted_urls = process_txt_from_HcApp(Text_message)

    if List_of_extracted_urls == 0:
        #print("There is no url in the text!")
        final_result['result'] = ' None'
        final_result['reason'] = ' There is no url in the text!'
        return final_result

    else:
        result = url_first_check(List_of_extracted_urls)
        # goto_url_advanced_analysis(result)
        if not (goto_url_advanced_analysis(result)):
            print("Just First check!")
            final_result['result'] = ' Not Safe '
            final_result['reason'] = ' Bad reputation or already malicious! '

        else:
            print("GO to advanced Analysis!")
            print(advanced_url_analysis(List_of_extracted_urls))
            if advanced_url_analysis(List_of_extracted_urls) == 1:
                final_result['result'] = ' Not Safe'
                final_result['reason'] = ' This url contains malicious links or may redirect to malicious pages!'

            else:
                final_result['result'] = ' Safe'
                final_result['reason'] = ' Nothing found after analysis'
    return(final_result)

Text_message = sys.argv[1]
print(url_analysis(Text_message))

# text = sys.argv[1]
# print(process_txt_from_HcApp())
# goto_url_advanced_analysis()
