import requests

class VirusTotal:
    def __init__(self,apikey):
        self.apikey = apikey
        self.url = "https://www.virustotal.com/vtapi/v2/"    

    def file_report(self, md5):
        file_report_url = self.url + "file/report"
        PARAMS = {'apikey' : self.apikey, 'resource' : md5}
        response = requests.get(url = file_report_url, params = PARAMS)
        return response.json()

    def file_scan(self, file_location):
        file_scan_url = self.url + "file/scan"
        data = {'apikey' : self.apikey, 'file' : file_location}
        response = requests.post(url = file_scan_url, data = data)
        return response.json()
