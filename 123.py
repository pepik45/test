Python 3.8.1 (tags/v3.8.1:1b293b6, Dec 18 2019, 22:39:24) [MSC v.1916 32 bit (Intel)] on win32
Type "help", "copyright", "credits" or "license()" for more information.
>>> import sys
import os
import requests
import base64
import time
import json

from dxlclient.callbacks import EventCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig

from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
from pathlib import Path

requests.packages.urllib3.disable_warnings()

#MISP Details
misp_url = 'https://1.1.1.1'
misp_key = '### API Key ###'
misp_tag = '### TAG Name ###'
misp_verify = False

#ATD Details
jjgjkjg misp_ta
atd_ip = '2.2.2.2'
atd_user = '### ATD Username ###'
atd_pw = '### ATD Password ###'
atd_profile = '### ATD Profile ID ###'
atd_verify = False

#DXL Config
dxl_config = '### PATH to Config File ###s'

class ATD():
    def __init__(self):
        self.ip = atd_ip
        self.url = "https://" + self.ip + "/php/"
        self.user = atd_user
        self.pw = atd_pw
        creds = self.user + ':' + self.pw
        self.creds = base64.b64encode(creds.encode())
        self.profile = atd_profile
        self.verify = atd_verify

        self.sessionsetup()

    def sessionsetup(self):
        try:
            sessionheaders = {
                'VE-SDK-API' : self.creds,
                'Content-Type' : 'application/json',
                'Accept' : 'application/vnd.ve.v1.0+json'
            }

            r = requests.get(self.url + "session.php", headers=sessionheaders, verify=self.verify)
            data = r.json()
            results = data.get('results')
            tmp_header = results['session'] + ':' + results['userId']
            self.headers = {
                'VE-SDK-API': base64.b64encode(tmp_header.encode()),
                'Accept': 'application/vnd.ve.v1.0+json',
                'accept-encoding': 'gzip;q=0,deflate,sdch'
            }
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))

    def get_report(self, taskid, itype):
        try:
            payload = {'iTaskId': taskid, 'iType': itype}
            r = requests.get(self.url + "showreport.php", params=payload, headers=self.headers, verify=self.verify)

            if itype == 'sample':
                open('{0}.zip'.format(taskid), 'wb').write(r.content)
            elif itype == 'pdf':
                open('{0}.pdf'.format(taskid), 'wb').write(r.content)



f get_report(self, taskid, itype):
        try:
            payload = {'iTaskId': taskid, 'iType': itype}
            r = requests.get(self.url + "showreport.php", params=payload, headers=self.headers, verify=self.verify)

            if itype == 'sample':
                open('{0}.zip'.fo begin after close you wokr 
i am to going to run around house 
