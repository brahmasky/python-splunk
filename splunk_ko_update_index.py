# from https://github.com/harsmarvania57/splunk-ko-change/blob/master/ko_change.py

from __future__ import print_function
from builtins import input
from io import open
import os
import sys
from splunk import mergeHostPath
import splunk.rest as rest
import splunk.auth as auth
import splunk.entity as entity
import json
import argparse
import getpass
import re
import csv
from datetime import datetime


ko_details = []
## Global vars, update according to your env
# setting default usename and password for the session
username = ''
password = ''
# setting path
result_file='./result.{}.csv'.format(datetime.now().strftime('%Y%m%d_%H%M%S'))

# Argument parser


def argument_parser():
    try:
        parser = argparse.ArgumentParser(
            description='List/Transfer ownership/permission of splunk knowledge objects.')
        subparsers = parser.add_subparsers(
            dest='subp_flag', help='Command Choices')

        # Create argument parser to list the data
        list_parser = subparsers.add_parser(
            'list', help='List splunk knowledge objects')
        if sys.version_info[0] < 3:
            list_ko_subparser = list_parser.add_subparsers(
                dest='list_ko_type', help='Knowledge Object Choices')
        else:
            list_ko_subparser = list_parser.add_subparsers(
                dest='list_ko_type', required=True, help='Knowledge Object Choices')

        # Create argument parser for updating indexes of Knowledge objects
        update_parser = subparsers.add_parser(
            'update', help='Update indexes in knowledge objects based on index mapping file')
        if sys.version_info[0] < 3:
            update_ko_subparser = update_parser.add_subparsers(
                dest='update_ko_type', help='Knowledge Object Choices')
        else:
            update_ko_subparser = update_parser.add_subparsers(
                dest='update_ko_type', required=True, help='Knowledge Object Choices')

        ko_type_args = ['macro', 'savedsearch', 'dashboard', 'eventtype', 'lookupdef', 'lookupfile',
                        'tag', 'field_extraction', 'panel', 'field_transformation', 'workflow_action']

        for i in ko_type_args:
            lkp = list_ko_subparser.add_parser(i, help='To list ' + i)
            lkp_grp = lkp.add_mutually_exclusive_group(required=True)
            lkp.add_argument('--filter', required=False, help='Filter by name')
            lkp.add_argument('--host', required=False,
                             help='Specify splunk server to connect to (defaults to local server)')
            lkp_grp.add_argument('--user', required=False, help='Username')
            lkp_grp.add_argument('--file', required=False,
                                 help='Filename containing KO Title')

            ukp = update_ko_subparser.add_parser(
                i, help='To update indexes in ' + i)
            ukp_grp = ukp.add_mutually_exclusive_group(required=True)
            ukp_grp.add_argument('--user', required=False, help='Username')
            ukp_grp.add_argument('--file', required=False,
                                 help='Filename containing KO Title')
            ukp.add_argument('--mapping', required=True,
                             help='Filename container old to new index mapping')
            ukp.add_argument('--filter', required=False, help='Filter by name')
            ukp.add_argument('--host', required=False,
                             help='Specify splunk server to connect to (defaults to local server)')

        # Print help if no option provided
        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

        args = parser.parse_args()

        if args.subp_flag == 'list':
            return args.subp_flag, args.list_ko_type, args.host, args.filter, args.user, args.file
        elif args.subp_flag == 'update':
            return args.subp_flag, args.update_ko_type, args.host, args.filter, args.user, args.file, args.mapping

    except:
        raise


def user_check(ko_value):
    try:
        # username = os.environ.get('splunkusername', '')
        global username
        global password
        if username == "":
            username = input('Enter username with admin privileges: ')
        # password = os.environ.get('splunkpassword', '')
        if password == "":
            password = getpass.getpass('Enter password: ')
        session_key = auth.getSessionKey(username, password)
        # if session_key:
        #     print('### the session key for {} is {}'.format(username, session_key))

        # Check new owner exist or not
        if ko_value[0] == 'change':
            new_owner = ko_value[4]
            if new_owner:
                userlist = auth.getUser(name=new_owner)
                if not userlist:
                    print('New owner ' + new_owner + ' not found in splunk')
                    sys.exit(1)
        return session_key
    except:
        raise

# Check Role


def role_check(role):
    try:
        getrole = auth.listRoles(count=0)
        if role not in getrole:
            print('Role ' + role + ' not found in splunk')
            sys.exit(1)
        return True
    except:
        raise

# Check app


def app_check(app, session_key):
    try:
        getapp = list(entity.getEntities('apps/local', search='visible=1 AND disabled=0',
                                         namespace=None, count=-1, sessionKey=session_key).keys())

        if app not in getapp:
            print('App ' + app + ' not found in splunk')
            sys.exit(1)
        return True
    except:
        raise

# Retrieve knowledge objects for user


def retrieve_content(session_key, ko_type, owner, file=None, filter=None):
  try:
      # For Saved Searches
      if ko_type == 'savedsearch':
          config_endpoint = '/servicesNS/-/-/saved/searches'
      # For Dashboards
      elif ko_type == 'dashboard':
          config_endpoint = '/servicesNS/-/-/data/ui/views'
      elif ko_type == 'eventtype':
          config_endpoint = '/servicesNS/-/-/saved/eventtypes'
      # For Lookup Definitions
      if ko_type == 'macro':
          config_endpoint = '/servicesNS/-/-/configs/conf-macros'
      # For macros
      elif ko_type == 'lookupdef':
          config_endpoint = '/servicesNS/-/-/data/transforms/lookups'
      # For Lookup Files
      elif ko_type == 'lookupfile':
          config_endpoint = '/servicesNS/-/-/data/lookup-table-files'
      # For Tags
      elif ko_type == 'tag':
          config_endpoint = '/servicesNS/-/-/saved/fvtags'
      # For Field Extractions
      elif ko_type == 'field_extraction':
          config_endpoint = '/servicesNS/-/-/data/props/extractions'
      # For Panels
      elif ko_type == 'panel':
          config_endpoint = '/servicesNS/-/-/data/ui/panels'
      # For Field Transformations
      elif ko_type == 'field_transformation':
          config_endpoint = '/servicesNS/-/-/data/transforms/extractions'
      # For Workflow Actions
      elif ko_type == 'workflow_action':
          config_endpoint = '/servicesNS/-/-/data/ui/workflow-actions'

      # Get Argument
      if ko_type == 'savedsearch':
          get_argument = {'output_mode': 'json', 'count': 0, 'add_orphan_field': 'yes', 'f': ['disabled', 'orphan', 'search']}
      elif ko_type == 'dashboard' :
          get_argument = {'output_mode': 'json', 'count': 0,  'f': ['disabled', 'eai:data']}
      elif ko_type == 'eventtype' :
          get_argument = {'output_mode': 'json', 'count': 0,  'f': ['disabled', 'search']}
      elif ko_type == 'macro' :
          get_argument = {'output_mode': 'json', 'count': 0,  'f': ['disabled', 'definition']}
      else:
          get_argument = {'output_mode': 'json', 'count': 0, 'f': ['disabled']}

      if filter:
          get_argument = json.loads(json.dumps(get_argument))
          get_argument['search'] = str(filter)
      (response, content) = rest.simpleRequest(
          config_endpoint, session_key, getargs=get_argument, timeout=500)
  except:
      raise

  ko_config = json.loads(content)
  # print('###\n{}\n###'.format(ko_config))
  ko_details.append(['App', 'Author', 'Name', 'KO Type', 'Disabled', 'Data', 'List URL', 'Permission', 'Read Perm', 'Write Perm', 'Orphan'])
  ko_details.append(['===========', '===========', '===========', '===========', '===========', '===========', '===========', '===========', '===========', '===========', '==========='])

  # Search knowledge objects for user from all users output and append into ko_details list.
  for i in range(len(ko_config['entry'])):
      if owner:
          if 'author' in ko_config['entry'][i]:
              author_name = ko_config['entry'][i]['author']
          else:
              author_name = owner

          if author_name == owner:
              # ko_title = ko_config['entry'][i]['title']
              app_name = ko_config['entry'][i]['acl']['app']
              ko_name = ko_config['entry'][i]['name']
              disabled = str(ko_config['entry'][i]['content']['disabled'])
              sharing = ko_config['entry'][i]['acl']['sharing']
              list_url = ko_config['entry'][i]['links']['list']
              
              if ko_type == 'savedsearch':
                  orphan = str(ko_config['entry'][i]['content']['orphan'])
                  data = ko_config['entry'][i]['content']['search']
                  # scheduled = str(ko_config['entry'][i]['content']['is_scheduled'])
              elif ko_type == 'dashboard':
                  data = ko_config['entry'][i]['content']['eai:data']
                  orphan = 'N/A'
              elif ko_type == 'eventtype':
                  data = ko_config['entry'][i]['content']['search']
                  orphan = 'N/A'
              elif ko_type == 'macro':
                  data = ko_config['entry'][i]['content']['definition']
                  orphan = 'N/A'
              else:
                  orphan = 'N/A'
                  data = 'N/A'
              # print('disable == {} and sharing == {}'.format(disabled,sharing))

              if ko_config['entry'][i]['acl']['perms'] is not None:
                  if 'read' in ko_config['entry'][i]['acl']['perms']:
                      read_perm = ','.join(
                          ko_config['entry'][i]['acl']['perms']['read'])
                  else:
                      read_perm = 'None'

                  if 'write' in ko_config['entry'][i]['acl']['perms']:
                      write_perm = ','.join(
                          ko_config['entry'][i]['acl']['perms']['write'])
                  else:
                      write_perm = 'None'
              else:
                  read_perm = 'None'
                  write_perm = 'None'
              # ignore disabled and private KOs              
          
              if not ((disabled == 'True') or sharing == 'user'):
                  ko_details.append([app_name, author_name, ko_name, ko_type, disabled, data, list_url,
                                    sharing, read_perm, write_perm, orphan])
                              
      if file:
          with open(file, encoding='utf-8') as read_f:
              f_content = read_f.read().splitlines()
          for f_name in f_content:
              ko_name = ko_config['entry'][i]['name']
              if f_name == ko_name:
                  app_name = ko_config['entry'][i]['acl']['app']
                  author_name = ko_config['entry'][i]['author']
                  disabled = str(ko_config['entry'][i]['content']['disabled'])
                  sharing = ko_config['entry'][i]['acl']['sharing']
                  list_url = ko_config['entry'][i]['links']['list']
                  if ko_type == 'savedsearch':
                      orphan = str(ko_config['entry'][i]['content']['orphan'])
                      data = ko_config['entry'][i]['content']['search']
                      # scheduled = str(ko_config['entry'][i]['content']['is_scheduled'])
                  elif ko_type == 'dashboard':
                      data = ko_config['entry'][i]['content']['eai:data']
                      orphan = 'N/A'
                  elif ko_type == 'eventtype':
                      data = ko_config['entry'][i]['content']['search']
                      orphan = 'N/A'
                  elif ko_type == 'macro':
                      data = ko_config['entry'][i]['content']['definition']
                      orphan = 'N/A'
                  else:
                      orphan = 'N/A'
                      data = 'N/A'

                  if ko_config['entry'][i]['acl']['perms'] is not None:
                      if 'read' in ko_config['entry'][i]['acl']['perms']:
                          read_perm = ','.join(
                              ko_config['entry'][i]['acl']['perms']['read'])
                      else:
                          read_perm = 'None'

                      if 'write' in ko_config['entry'][i]['acl']['perms']:
                          write_perm = ','.join(
                              ko_config['entry'][i]['acl']['perms']['write'])
                      else:
                          write_perm = 'None'
                  else:
                      read_perm = 'None'
                      write_perm = 'None'

                  if not ((disabled == 'True') or sharing == 'user'):
                      ko_details.append([app_name, author_name, ko_name, ko_type, disabled, data, list_url,
                                        sharing, read_perm, write_perm, orphan])


  # Check if user have any knowledge object or not and then print message and exit the script if no knowledge objects found.
  if len(ko_details) <= 2:
      print('No ' + ko_type + ' found')
      sys.exit(1)
  else:
      print('Total ' + str(len(ko_details)-2) + ' ' + ko_type + ' found')
      col_array = []

      # Searching maximum length for every row in each column and adding 2 for padding & store them into col_array list
      for col in zip(*ko_details):
          col_width = max(len(string) for string in col) + 2
          col_array.append(col_width)

      # Print ko_details list and inogre details after column 6
      for row in ko_details:
          j = 0
          print('')
          for index, string in enumerate(row):
              # print('### index == {}, string == {}'.format(index,string))
              if index < 5:
                  print(''.join(string.ljust(col_array[j])), end=' ')
              j = j + 1

      print('\n')
      return ko_details, col_array

def read_csv(filename): 
  with open(filename, 'r') as f:
    r = csv.reader(f, delimiter=',')
    next(r)  # skip header line
    return list(r)

def write_csv(filename, ko_details):
  fields=ko_details[0]
  with open(filename, 'wb') as csvfile:
    csvwriter = csv.writer(csvfile)   
    csvwriter.writerow(fields)
    for row in ko_details[2:]:
      csvwriter.writerow(row)

def update_index(session_key, ko_type, owner, file=None, filter=None, mapping=None):
    try:
      ## Retrieve knowledge objects
      (ko_details, col_array) = retrieve_content(session_key, ko_type, owner, file, filter)
      col_array.append(9)
      # Append new column "New Search" in ko_details list.
      ko_details[0].append('New Data')
      ko_details[1].append('========')
      # Append new column "Status" in ko_details list as the last column
      col_array.append(12)
      ko_details[0].append('Status')
      ko_details[1].append('========')

      for row in ko_details[:2]:
          j = 0
          print('')
          for index, string in enumerate(row):
              if index < 5 or index > 11:
                  print(''.join(string.ljust(col_array[j])), end=' ')
              j = j + 1
      print('\n')

      ## Use regex to extract old index name
      # [app_name, author_name, ko_name, ko_type, disabled, scheduled, list_url, sharing, read_perm, write_perm, orphan, search, new_search, status]
      for row in ko_details[2:]:
        # Fetching index for value in list and append value
        data_index = ko_details.index(row)
        app_name = row[0]
        ko_name = row[2]
        list_url = row[6]
        data = row[5]

        indexes = re.findall('index\s*=[\s\=\"\'\(]*([0-9_a-zA-Z]+)', data, flags = re.DOTALL | re.I)
        # print('### indexes found: {}'.format(indexes))

        replacements = []
        data_changed = False
        for index in set(indexes):
          for line in read_csv(mapping):
            # If old index exists in index mapping, update the replacement list with 
            if(index.lower() == line[0] and line[1] not in indexes):
              # print('### index.lower() = {}, old index in mapping = {} '.format(index.lower(), line[0]))
              replacements.append((index, 'index={} OR index={}'.format(index.lower(), line[1])))
              # print('### replacements == {}'.format(replacements))

        # update indexes in old search data, for example 'index=_internal' to 'index=_internal OR index=_external'
        if len(replacements) > 0:
          for (pat, repl) in replacements:
            data = re.sub(r'index\s*=[\s\=\"\'\(]*({})[\"\'\)]*'.format(pat), repl, data, flags = re.I)
          data_changed = True

        # only update the KO if the mapping has been done
        if data_changed:
          # update ko_details with the new data 
          ko_details[data_index].append(data)
          # Let user to confirm if the new data is valid
          user_input = input('\033[93mDo you want to update \033[4m{}\033[0m \033[92m\033[1m\'{}\'\033[0m \033[93min app \033[94m{}\033[0m \033[93mwith the following now?\033[0m\033[91m[y/n]\033[0m\n\033[96m{}...\033[0m\n'.format(ko_type, ko_name, app_name, data[0:200])).lower()

          if(user_input == 'y'):
            if ko_type in ('savedsearch', 'eventtype') :
              post_argument = {'search': data}
            elif ko_type == 'dashboard':
              post_argument = {'eai:data': data}
            elif ko_type in ('macro'):
              post_argument = {'definition': data}
            # print(post_argument)

            # Post the new data and update ko_datails
            try:
                rest.simpleRequest(list_url, sessionKey=session_key, postargs=post_argument, method='POST', raiseAllErrors=True)
                ko_details[data_index].append('Updated')
                ko_array_value = ko_details[data_index]
                j = 0
                print('')
                
                for index, string in enumerate(ko_array_value):
                    if index < 5 or index > 11:
                        print(''.join(string.ljust(col_array[j])), end=' ')
                    j = j + 1
            except:
                data_index = ko_details.index(row)
                ko_details[data_index].append('Failed')
                ko_array_value = ko_details[data_index]
                j = 0
                print('')
                
                for index, string in enumerate(ko_array_value):
                    if index < 5 or index > 11:
                        print(''.join(string.ljust(col_array[j])), end=' ')
                    j = j + 1
                # pass

          # User may not want to update the data if spotted some incorrect mapping
          if(user_input == 'n'):
            data_index = ko_details.index(row)
            ko_details[data_index].append('Not Updated')
            ko_array_value = ko_details[data_index]
            j = 0
            print('')
            
            for index, string in enumerate(ko_array_value):
                if index < 5 or index > 11:
                    print(''.join(string.ljust(col_array[j])), end=' ')
                j = j + 1

          print('\n')
        else:
          data_index = ko_details.index(row)
          # no new search to be updated
          ko_details[data_index].append('N/A')
          # update status=Not Mapped
          ko_details[data_index].append('Not Mapped')

      # Save status into a result file
      write_csv(result_file, ko_details)
        

    except:
        raise


def main():
    # Call argument_parser function and store returned value into ko_value variable
    ko_value = argument_parser()

    if ko_value[2] != "":
        mergeHostPath(ko_value[2], True)

    session_key = user_check(ko_value)

    ko_type = ko_value[1]
    filter = ko_value[3]
    owner = ko_value[4]
    file = ko_value[5]

    # Retrieve knowledge objects
    if ko_value[0] == 'list':
        retrieve_content(session_key, ko_type, owner, file, filter)

    elif ko_value[0] == 'update':
        mapping_file = ko_value[6]

        update_index(session_key, ko_type, owner, file, filter, mapping_file)


if __name__ == '__main__':
    try:
        main()
    except:
        raise
