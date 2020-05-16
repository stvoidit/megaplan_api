# megaplan_api

## Megaplan_Auth
Получение ключей / токенов для работы с АПИ

    accessid, secretkey = Megaplan_Auth('login', 'password', 'host').get_key()

## Megaplan_Api
### Пример GET
https://dev.megaplan.ru/r1905/api/API_tasks.html#api-task-list

    my_host = 'jobdomain.ru'
    api = Megaplan_Api(accessid, secretkey, my_host)

    query_url = '/BumsTaskApiV01/Task/list.api'
    get_query = api.get_query(query_url, {"Folder":"all", "Status": "any"})

### Пример POST
https://dev.megaplan.ru/r1905/api/API_deals.html#api-deals-save

    payload = {
                'ProgramId': 41,
                'Model[Description]': 'Описание сделки',
                'Model[Cost][Value]': 2433.23,
                'Model[Category1000063CustomFieldOpisanie]': 'Кастомное поле'
            }
    api = Megaplan_Api(accessid, secretkey, my_host)
    post_query = api.post_query('/BumsTradeApiV01/Deal/save.api', payload)

