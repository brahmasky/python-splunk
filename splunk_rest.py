import requests, json, logging
from xml.dom import minidom
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def main():
  base_url = 'https://localhost:8089'
  username = 'admin'
  password = 'changme'

  login_url = f'{base_url}/servicesNS/-/-/auth/login'
  rest_url = f'{base_url}/services/search/jobs/export'
  search_data = {'search': 'search index=_internal earliest=-1h@h |stats count by source',
              'output_mode': 'csv'}
  

  try:
    r = requests.get(login_url,
      data={'username':username,'password':password}, verify=False)
  except InsecureRequestWarning:
    pass

  # print('r = {}'.format(r.text))

  session_key = minidom.parseString(r.text).getElementsByTagName('sessionKey')[0].firstChild.nodeValue

  print('session key = {}'.format(session_key))

  # print('search_data = {}'.format(search_data))
  r = requests.post(rest_url, data=search_data,
    headers = { 'Authorization': 'Splunk {}'.format(session_key)},
    verify = False)

  print('r = {}'.format(r.text))


if __name__ == "__main__":
    main()