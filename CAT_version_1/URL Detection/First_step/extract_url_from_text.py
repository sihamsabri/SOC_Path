import re

def Find_urls_from_text(text_message):

    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex, text_message)
    #print(url)
    extracted_urls = [x[0] for x in url]
    if extracted_urls == []:
        return 0
    return extracted_urls

# Let's test it with an example:
# string = 'My Repo at GitLab is :  http://auth.geeksforgeeks.org/user/Chinmoy%20Lenka/articles ' \
#       'in the portal of https://www.geeksforgeeks.org/ and www.google.com'

# print("Urls: ", Find_urls_from_text(string))