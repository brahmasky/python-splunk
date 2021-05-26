import requests, json, logging
from xml.dom import minidom
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def auth_search():
  base_url = 'https://localhost:8089'
  username = 'admin'
  password = 'changeme'

  login_url = f'{base_url}/servicesNS/-/-/auth/login'
  rest_url = f'{base_url}/services/search/jobs/export'
  search_data = {'search': 'search index=_internal earliest=-1h@h |stats count by source',
              'output_mode': 'csv'}
  
  # login to get a session key
  try:
    r = requests.get(login_url,
      data={'username':username,'password':password}, verify=False)
  except InsecureRequestWarning:
    pass
  except e:
    print(exception)

  # print('r = {}'.format(r.text))

  session_key = minidom.parseString(r.text).getElementsByTagName('sessionKey')[0].firstChild.nodeValue

  # print('session key = {}'.format(session_key))
  header = { 'Authorization': 'Splunk {}'.format(session_key)}
  # print('header ==  {}'.format(header))

  # post the search data with session key as the Authroization header  
  try:
    r = requests.post(rest_url, 
                        data=search_data,
                        headers = header,
                        verify = False)
  except e:
    print(exception)

  print('Result: \n{}'.format(r.text))

def search():
  base_url = 'https://localhost:8089'

  # construct basic auth info
  username = 'admin'
  password = 'changeme'
  auth_data=(username, password)

  rest_url = f'{base_url}/services/search/jobs/export'

  # construct search payload
  search_base = 'search '
  spl = 'index=_internal earliest=-1h@h |stats count by source'
  mode = 'csv'
  search_data = {'search': f'{search_base}{spl}',
              'output_mode': mode}

  print(search_data)
  # post_data = {**auth_data, **search_data}
  # print('post_data == {}'.format(post_data))
  
  # try to search in one shot
  try:
    r = requests.post(rest_url, auth=auth_data,
                      data=search_data, 
                      verify=False)
  except InsecureRequestWarning:
    pass
  except e:
    print(e)

  print('Result: \n{}'.format(r.text))


def main():
  search()


if __name__ == "__main__":
    main()
