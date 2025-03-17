import json
# -*- coding: utf-8 -*-
__version__ = '1.1.0'
import sys
from hashlib import sha1, md5
from collections import OrderedDict
if sys.version_info.major > 2:
    from urllib.parse import urlencode
else:
    from urllib import urlencode
import hmac
import requests
import base64
import sys

class ZadarmaAPI(object):

    def __init__(self, key, secret, is_sandbox=False):
        """
        Constructor
        :param key: key from personal
        :param secret: secret from personal
        :param is_sandbox: (True|False)
        """
        self.key = key
        self.secret = secret
        self.is_sandbox = is_sandbox
        self.__url_api = 'https://api.zadarma.com'
        if is_sandbox:
            self.__url_api = 'https://api-sandbox.zadarma.com'

    def call(self, method, params={}, request_type='GET', format='json', is_auth=True):
        """
        Function for send API request
        :param method: API method, including version number
        :param params: Query params
        :param request_type: (get|post|put|delete)
        :param format: (json|xml)
        :param is_auth: (True|False)
        :return: response
        """
        request_type = request_type.upper()
        if request_type not in ['GET', 'POST', 'PUT', 'DELETE']:
            request_type = 'GET'
        params['format'] = format
        auth_str = None
        is_nested_data = False
        for k in params.values():
            if not isinstance(k, str):
                is_nested_data = True
                break
        if is_nested_data:
            params_string = self.__http_build_query(OrderedDict(sorted(params.items())))
            params = params_string
        else:
            params_string = urlencode(OrderedDict(sorted(params.items())))

        if is_auth:
            auth_str = self.__get_auth_string_for_header(method, params_string)

        if request_type == 'GET':
            result = requests.get(self.__url_api + method + '?' + params_string, headers={'Authorization': auth_str})
        elif request_type == 'POST':
            result = requests.post(self.__url_api + method, headers={'Authorization': auth_str}, data=params)
        elif request_type == 'PUT':
            result = requests.put(self.__url_api + method, headers={'Authorization': auth_str}, data=params)
        elif request_type == 'DELETE':
            result = requests.delete(self.__url_api + method, headers={'Authorization': auth_str}, data=params)
        return result.text

    def __http_build_query(self, data):
        parents = list()
        pairs = dict()

        def renderKey(parents):
            depth, outStr = 0, ''
            for x in parents:
                s = "[%s]" if depth > 0 or isinstance(x, int) else "%s"
                outStr += s % str(x)
                depth += 1
            return outStr

        def r_urlencode(data):
            if isinstance(data, list) or isinstance(data, tuple):
                for i in range(len(data)):
                    parents.append(i)
                    r_urlencode(data[i])
                    parents.pop()
            elif isinstance(data, dict):
                for key, value in data.items():
                    parents.append(key)
                    r_urlencode(value)
                    parents.pop()
            else:
                pairs[renderKey(parents)] = str(data)

            return pairs
        return urlencode(r_urlencode(data))

    def __get_auth_string_for_header(self, method, params_string):
        """
        :param method: API method, including version number
        :param params: Query params dict
        :return: auth header
        """
        data = method + params_string + md5(params_string.encode('utf8')).hexdigest()
        hmac_h = hmac.new(self.secret.encode('utf8'), data.encode('utf8'), sha1)
        if sys.version_info.major > 2:
            bts = bytes(hmac_h.hexdigest(), 'utf8')
        else:
            bts = bytes(hmac_h.hexdigest()).encode('utf8')
        auth = self.key + ':' + base64.b64encode(bts).decode()
        return auth



API_KEY = "4df1a833f09d4f0e62ed"
API_SECRET = "1cbe2259bacaf2d54836"

z_api = ZadarmaAPI(key=API_KEY,secret=API_SECRET)
call_id = sys.argv[1] #sys.argv[1] #data['body']['call_id_with_rec'] #"1742110200.136322"
pbx_call_id = sys.argv[2] #sys.argv[2] #'out_4675251dd3ca991ef7bc90e937aeceebe96f1951'


# сохраняем это в json
temp = json.loads(z_api.call('/v1/pbx/record/request/', {'call_id': call_id}))

#print(json.dumps(temp, indent=2))
# ЗДЕСЬ НАДО УКАЗАТЬ ПУТЬ ДО ПАПКИ С ФАЙЛАМИ MP3
file_path = f"/var/www/scripts/records/{call_id}.mp3"
if 'link' in temp:
    r = requests.get(temp['link'])
    # --- КОНВЕРТИРУЕМ mp3 в BASE64 ---
    print({'name':f"{call_id}.mp3"})
    # --- СОХРАНЯЕМ ФАЙЛ MP3 ---
    with open(f"{file_path}", "wb") as f:
        f.write(r.content)
