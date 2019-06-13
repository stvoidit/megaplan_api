# v-2.01

import requests
import hashlib
import hmac
import base64
from email.utils import formatdate
from urllib.parse import urlencode
import time
import datetime


class Megaplan_Auth:
    """
    api = Megaplan_Auth(login, password, host).get_key()

    login - Логин пользователя в системе Мегаплан\n
    password - Пароль пользователя от системы Мегаплан\n
    host - Домен вашего Мегаплан (без http*)\n
    __proto - По умолчанию HTTPS\n
    ----
    __password_crypt() - Шифрует пароль в md5\n
    __get_otk() - Получения OneTimeKey для получения следующих ключей\n
    get_key() - Возвращает кортеж из (str: AccessId, bytes: SecretKey)
    """
    __slots__ = ['login', 'password', 'host',
                 '__proto', 'accessid', 'secretkey']

    def __init__(self, login, password, host, proto='https://'):
        self.login = str(login).strip()
        self.password = self.__password_crypt(str(password).strip())
        self.host = str(host).strip()
        self.__proto = proto
        self.accessid, self.secretkey = self.get_key()

    def __password_crypt(self, password):
        return hashlib.md5(password.encode()).hexdigest()

    def __get_otk(self):
        return requests.post(self.__proto + self.host + '/BumsCommonApiV01/User/createOneTimeKeyAuth.api', headers={
            'Accept': 'application/json'}, data={'Login': self.login, 'Password': self.password}).json()['data']['OneTimeKey']

    def get_key(self):
        _authdata = requests.post(self.__proto + self.host + '/BumsCommonApiV01/User/authorize.api', headers={
            'Accept': 'application/json'}, data={'Login': self.login, 'Password': self.password, 'OneTimeKey': self.__get_otk()}).json()['data']
        _AccessId = _authdata['AccessId']
        _SecretKey = _authdata['SecretKey'].encode()
        return _AccessId, _SecretKey


class Megaplan_Api:
    __slots__ = ['_HOST', '_HOST_full', '_today',
                 'AccessId', 'SecretKey', 'host', 'proto', 'domain']

    def __init__(self, AccessId, SecretKey, host='control-mos.ru', proto='https://'):
        self.host = 'control-mos.ru'  # Хост
        self.proto = proto
        self.domain = self.proto + self.host  # протокол + хост
        self._today = formatdate(time.time())  # дата в стандарте RFC-2822
        self.AccessId = AccessId
        self.SecretKey = SecretKey

    def query_hasher(self, request_type, uri, payload=None):
        if request_type == 'GET':
            content_type = ''
        elif request_type == 'POST':
            content_type = 'application/x-www-form-urlencoded'
        if payload:
            uri = uri + '?' + urlencode(payload, doseq=True)
        query = request_type+'\n\n' + content_type + '\n' + \
            self._today+'\n' + self.host + uri
        hash_query = base64.b64encode(hmac.new(self.SecretKey, query.encode(),
                                               hashlib.sha1).hexdigest().encode()).decode()
        Auth_Heared = {
            'Date': self._today,
            'Accept': 'application/json',
            'X-Authorization': self.AccessId + ':' + hash_query
        }
        Auth_Heared.update(
            {'Content-Type': 'application/x-www-form-urlencoded'}) if content_type == 'POST' else None
        return Auth_Heared

    def get_query(self, uri_query, payload=''):
        head = self.query_hasher('GET', uri_query, payload)
        return requests.get(
            self.domain + uri_query,
            headers=head,
            params=urlencode(payload, doseq=True)).json()['data']

    def post_query(self, uri_query, payload):
        head = self.query_hasher('POST', uri_query, None)
        return requests.post(self.domain + uri_query, headers=head, data=payload).json()
