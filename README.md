# megaplan_api

## Megaplan_Auth
Получение ключей / токенов для работы с АПИ

    MP = Megaplan_Auth('login', 'password', 'host')
    a_key = MP.accessid
    s_key = MP.secretkey

Далее эти ключи используем для Megaplan_Api

## Megaplan_Api
### Пример GET
https://dev.megaplan.ru/r1905/api/API_tasks.html#api-task-list

    MP = Megaplan_Auth('login', 'password', 'host')
    a_key = MP.accessid
    s_key = MP.secretkey
    my_host = 'jobdomain.ru'
    query_url = '/BumsTaskApiV01/Task/list.api'
    get_query = Megaplan_Api(a_key, s_key, my_host).get_query(query_url, Folder='all', Status='any')

### Пример POST
https://dev.megaplan.ru/r1905/api/API_deals.html#api-deals-save

    payload = {
                'ProgramId': 41,
                'Model[Description]': 'Описание сделки',
                'Model[Cost][Value]': 2433.23,
                'Model[Category1000063CustomFieldOpisanie]': 'Кастомное поле'
            }
            
    post_query = Megaplan_Api(a_key, s_key, 'jobdomain.ru').post_query('/BumsTradeApiV01/Deal/save.api', payload)

