import requests

class VirusTotal:
    def __init__(self,apikey):
        self.apikey = apikey
        self.url = "https://www.virustotal.com/vtapi/v2/"    

    def file_report(self, md5):
        file_report_url = self.url + "file/report"
        params = {'apikey' : self.apikey, 'resource' : md5}
        response = requests.get(url = file_report_url, params = params)
        return response.json()

    def file_scan(self, file_location):
        file_scan_url = self.url + "file/scan"
        files = {'file' : (file_location, open(file_location,'rb'))}
        params = {'apikey' : self.apikey}
        response = requests.post(url = file_scan_url, files=files, params = params)
        return response.json()
    
    def url_report(self, url):
        url_report_url = self.url + "url/report"
        params = {'apikey' : self.apikey, 'resource' : url}
        response = requests.get(url = url_report_url, params = params)
        return response.json()

    def url_scan(self, url):
        url_scan_url = self.url + "url/scan"
        params = {'apiley' : self.apikey, 'url' : url}
        response = requests.post(url=url_scan_url, params = params)
        return response.json()
