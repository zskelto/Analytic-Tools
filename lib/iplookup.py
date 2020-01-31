import requests

url = "http://ip-api.com/json/"

def ip_lookup(ip):
    lookup_url = url + ip
    response = requests.get(url = lookup_url)
    return response.json()
