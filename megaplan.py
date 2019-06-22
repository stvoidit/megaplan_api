# v-2.05

import requests
import hashlib
import hmac
import base64
from email.utils import formatdate
from urllib.parse import urlencode
import time
import datetime


class Megaplan_Auth:
    __slots__ = ['login', 'password', 'host',
                 '__proto', 'accessid', 'secretkey', 'domain']

    def __init__(self, login, password, host, proto='https://'):
        self.login = login
        self.password = self.__password_crypt(password)
        self.host = host
        self.__proto = proto
        self.domain = self.__proto + self.host
        self.accessid, self.secretkey = self.get_key()

    def __password_crypt(self, password):
        return hashlib.md5(password.encode()).hexdigest()

    def __get_otk(self):
        return requests.post(self.domain + '/BumsCommonApiV01/User/createOneTimeKeyAuth.api', headers={
            'Accept': 'application/json'}, data={'Login': self.login, 'Password': self.password}).json()['data']['OneTimeKey']

    def get_key(self):
        _authdata = requests.post(self.domain + '/BumsCommonApiV01/User/authorize.api', headers={
            'Accept': 'application/json'}, data={'Login': self.login, 'Password': self.password, 'OneTimeKey': self.__get_otk()}).json()['data']
        _AccessId = _authdata['AccessId']
        _SecretKey = _authdata['SecretKey'].encode()
        return _AccessId, _SecretKey


class Megaplan_Api:
    __slots__ = ['_HOST', '_HOST_full', '_today',
                 'AccessId', 'SecretKey', 'host', 'proto', 'domain']

    def __init__(self, AccessId, SecretKey, host=, proto='https://'):
        self.host = host  # Хост
        self.proto = proto
        self.domain = self.proto + self.host
        self._today = formatdate(time.time())
        self.AccessId = AccessId
        self.SecretKey = SecretKey

    def query_hasher(self, request_type, uri, payload=None):
        if payload:
            uri = uri + '?' + urlencode(payload, doseq=True)
        query = request_type+'\n\n' + 'application/x-www-form-urlencoded' + '\n' + \
            self._today+'\n' + self.host + uri
        hash_query = base64.b64encode(hmac.new(
            self.SecretKey,
            query.encode(),
            hashlib.sha1).hexdigest().encode()
        ).decode()
        Auth_Heared = {
            'Date': self._today,
            'Accept': 'application/json',
            'X-Authorization': self.AccessId + ':' + hash_query,
            'Content-Type': 'application/x-www-form-urlencoded',
            'accept-encoding': 'gzip, deflate, br'
        }
        return Auth_Heared

    def get_query(self, uri_query, payload=None):
        head = self.query_hasher('GET', uri_query, payload)
        return requests.get(
            self.domain + uri_query,
            headers=head,
            params=urlencode(payload, doseq=True)).json()

    def post_query(self, uri_query, payload):
        head = self.query_hasher('POST', uri_query, None)
        return requests.post(self.domain + uri_query, headers=head, data=payload).json()
