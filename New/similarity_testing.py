import numpy as np
import Levenshtein

# import matplotlib.pyplot as plt

############### The following function returns a list of the final results: malicious/safe urls ###############
def url_result(levenshtein_scores,threshold):
    urls_result = []
    for score in levenshtein_scores:
        if score >= threshold:
            urls_result.append(1)
        else:
            urls_result.append(0)
    return urls_result

def calculate_similarity(blacklist_file,urls_list):
    with open(blacklist_file, 'r') as f:
        blacklist = f.read().splitlines()

    # processed_blacklist = [url.lower().split('//')[1].split('/')[0] for url in blacklist] #
    # processed_url = [url.lower().split('//')[1].split('/')[0] for url in urls_list] #

    processed_blacklist = [url.lower().split('//')[1] for url in blacklist]
    processed_url = [url.lower().split('//')[1] for url in urls_list]
    # print("print") #
    # print(processed_url) #
    levenshtein_scores = []
    for url in processed_url:
        similarity_scores = [Levenshtein.ratio(url, black_url) for black_url in processed_blacklist]
        levenshtein_scores.append(np.max(similarity_scores))


    threshold = 0.65
    # print(url_result(levenshtein_scores, threshold))
    # print(levenshtein_scores)
    # plt.plot(levenshtein_scores)
    # plt.axhline(y=0.65, color='r', linestyle='--', label='Threshold')
    # plt.xlabel('URL index')
    # plt.ylabel('Similarity score')
    # plt.legend()
    # plt.show()
    return levenshtein_scores

# Urls=['http://t.honker.info:8/mypage.exe','https://airpurifiersystem.new/pages.php','http://sebastianbernal.new/mypage.php',

#    'http://autotpad.online.new/mygame.exe','https://auth.geeksforgeeks.org/user/Chinmoy%20Lenka/articles',
#    'https://www.geeksforgeeks.org/','https://auth.geeksforgeeks.org/user/Chinmoy%20Lenka/articles',
#    'https://www.geeksforgeeks.org/','https://skillupindia.real/mypage.php',
#    'https://volcanopowerplantnew.new/freegames.php',
#    'https://webgrowthnew.ma/file.php',
#    'https://citydeslacs.com/page.php',
#    'https://vividfashionsnew.available.com/mypage.php',
#    'https://newpaydayloansonline.net/MIR.apk',
#    'https://guiazeroestrias.com/mypage.php',
#    'https://erp50.com/APSI.exe',
#    'https://dfresh.online/',
#    'https://dfreshapp.online/',
#    'https://clickcomprasonline.com/',
#    'https://barkomsales.online/',
#    'https://bastisveep.online/]'
#    ]

# calculate_similarity('output.txt',Urls)