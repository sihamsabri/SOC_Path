import json
import requests
import socket

# The following function gives the ip reputation of an url based on virustotal API (Freemium)
# Urls_list = ["www.google.com", "www.youtube.com"]

def ip_reputation(urls_list):

    domains_list = []
    address_list = []
    reputation_list = []
    domain_reputation = []

    # with open("urls.txt", 'r') as f:
    # urls_list = f.readlines()

    for url in urls_list:
        url = url.strip()
        domain = url.split('//')[-1].split('www.')[-1].split('/')[0]
        domains_list.append(domain)

    # print(domains_list)
    # Domain reputation

    for dom in domains_list:
        Api = 'https://www.virustotal.com/api/v3/domains/'+ dom
        # This is the key for Authentication
        params = {'X-Apikey': '9722fbc98604f48474468ab356ec3de25a3ee71a35e8088463e96a1b1d4779bd'}
        # Launch the GET request
        response = requests.get(Api, headers=params)

        if response.status_code == 200:
            part1 = json.loads(response.text)
            # print(response.text)
            part2 = part1['data']
            final_result = part2['attributes']
            domain_reputation.append(final_result["last_analysis_stats"])
            # print(part1)

        else:
            domain_reputation.append("?")
    # print(domains_list)
    # print(domain_reputation)

    result = domain_reputation
    Final_domain_reputation_list = []
    for elm in result:
        if elm == '?':
            Final_domain_reputation_list.append('?')
        elif elm['harmless'] > elm['malicious']:
            Final_domain_reputation_list.append(0)
        else:
            Final_domain_reputation_list.append(1)

    # print(Final_reputation_list)
    # The following script is for translating the domain name into an ip address

    ########################

    for dom in domains_list:

        try:
            # Get the ip address from the url
            ip_address = socket.gethostbyname(dom)
            address_list.append(ip_address)

            # This exception is when we can not reach out the original server of an URL

        except socket.gaierror as e:

            address_list.append("?")

    # print(address_list)

    for ip in address_list:

        Api = 'https://www.virustotal.com/api/v3/ip_addresses/'+ ip
            # This is the key for Authentication

        params = {'X-Apikey': '9722fbc98604f48474468ab356ec3de25a3ee71a35e8088463e96a1b1d4779bd'}
            # Launch the GET request

        response = requests.get(Api, headers=params)
        if response.status_code == 200:
            part1 = json.loads(response.text)
                # print(response.text)
            part2 = part1['data']
            final_result = part2['attributes']
            reputation_list.append(final_result["last_analysis_stats"])
            # print(part1)

        else:
            reputation_list.append("?")

    # return (reputation_list)

    result = reputation_list
    Final_reputation_list = []
    for elm in result:

        if elm == '?':
            Final_reputation_list.append('?')
        elif elm['harmless'] > elm['malicious']:
            Final_reputation_list.append(0)
        else:
            Final_reputation_list.append(1)

    # print(Final_reputation_list)
    # print(Final_domain_reputation_list)
    if any(Final_reputation_list) or any(Final_domain_reputation_list):
        return 1
    return 0

    # Test
    # get_ip_add("www.youtube.com")


# harmless =
# print(ip_reputation(Urls_list))