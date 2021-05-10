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


ko_details = []

# Argument parser
def argument_parser():
    try:
        parser = argparse.ArgumentParser(description='List/Transfer ownership/permission of splunk knowledge objects.')
        subparsers = parser.add_subparsers(dest='subp_flag', help='Command Choices')
        
        # Create argument parser to list the data
        list_parser = subparsers.add_parser('list', help='List splunk knowledge objects')
        if sys.version_info[0] < 3:
            list_ko_subparser = list_parser.add_subparsers(dest='list_ko_name', help='Knowledge Object Choices')
        else:
            list_ko_subparser = list_parser.add_subparsers(dest='list_ko_name', required=True, help='Knowledge Object Choices')
        
        # Create argument parser for change permission of Knowledge objects
        change_parser = subparsers.add_parser('change', help='Change ownership, read & write permission and sharing of splunk knowledge objects')
        if sys.version_info[0] < 3:
            change_ko_subparser = change_parser.add_subparsers(dest='change_ko_name', help='Knowledge Object Choices')
        else:
            change_ko_subparser = change_parser.add_subparsers(dest='change_ko_name', required=True, help='Knowledge Object Choices')
        
        # Create argument parser for move of Knowledge objects 
        move_parser = subparsers.add_parser('move', help='Move knowledge objects to another app')
        if sys.version_info[0] < 3:
            move_ko_subparser = move_parser.add_subparsers(dest='move_ko_name', help='Knowledge Object Choices')
        else:
            move_ko_subparser = move_parser.add_subparsers(dest='move_ko_name', required=True, help='Knowledge Object Choices')
        
        ko_type_args = ['macro', 'savedsearch', 'dashboard', 'lookupdef', 'lookupfile', 'tag', 'field_extraction', 'panel', 'field_transformation', 'workflow_action', 'datamodel','eventtype','fieldalias','transforms_extract','command','panel','collection','modalert','nav']
        
        for i in ko_type_args:
            lkp = list_ko_subparser.add_parser(i, help='To list ' + i)
            lkp_grp = lkp.add_mutually_exclusive_group(required=True)
            lkp.add_argument('--filter', required=False, help='Filter by name')
            lkp.add_argument('--host', required=False, help='Specify splunk server to connect to (defaults to local server)')
            lkp_grp.add_argument('--user', required=False, help='Username')
            lkp_grp.add_argument('--file', required=False, help='Filename containing KO Title')
            ckp = change_ko_subparser.add_parser(i, help='To change acl of ' + i)
            ckp_grp = ckp.add_mutually_exclusive_group(required=True)
            ckp_grp.add_argument('--olduser', required=False, help='Old Username')
            ckp_grp.add_argument('--file', required=False, help='Filename containing KO Title')
            ckp.add_argument('--filter', required=False, help='Filter by name')
            ckp.add_argument('--host', required=False, help='Specify splunk server to connect to (defaults to local server)')
            ckp.add_argument('--newuser', required=False, help='New Username')
            ckp.add_argument('--sharing', required=False, help='New Sharing Permission')
            ckp.add_argument('--readperm', required=False, help='New Read Permission of KO')
            ckp.add_argument('--platform', required=True, help='Platform for the KO')
            mkp = move_ko_subparser.add_parser(i, help='To move ' + i + ' to another app')
            mkp_grp = mkp.add_mutually_exclusive_group(required=True)
            mkp_grp.add_argument('--user', required=False, help='Username')
            mkp_grp.add_argument('--file', required=False, help='Filename containing KO Title')
            mkp.add_argument('--filter', required=False, help='Filter by name')
            mkp.add_argument('--host', required=False, help='Specify splunk server to connect to (defaults to local server)')
            mkp.add_argument('--app', required=True, help='Move KO to specified app')

        # Print help if no option provided
        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)
            
        args = parser.parse_args()
        
        if args.subp_flag == 'list':
            return args.subp_flag, args.list_ko_name, args.host, args.filter, args.user, args.file
        elif args.subp_flag == 'change':
            if (args.newuser != None or args.sharing != None or args.readperm != None or args.platform != None):
                if args.sharing == 'user' and (args.readperm != None or args.writeperm != None):
                    parser.error('You can\'t supply --readperm or --platform or both with --sharing user')
                else:
                    return args.subp_flag, args.change_ko_name, args.host, args.filter, args.olduser, args.file, args.newuser, args.sharing, args.readperm, args.platform, args.host
            elif (args.newuser is None and args.sharing is None and args.readperm is None and args.writeperm is None):
                parser.error('Atleast one argument is required (--newuser, --sharing, --readperm, --platform)')
        elif args.subp_flag == 'move':
            return args.subp_flag, args.move_ko_name, args.host, args.filter, args.user, args.file, args.app
        
    except:
        raise

def user_check(ko_value):
    try:
        username = os.environ.get('splunkusername','')
        if username == "":
            username = input('Enter username with admin privileges: ')
        password = os.environ.get('splunkpassword','')
        if password == "":
            password = getpass.getpass('Enter password: ')
        session_key = auth.getSessionKey(username, password)
        
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
        getapp = list(entity.getEntities('apps/local', search='visible=1 AND disabled=0', namespace=None, count=-1, sessionKey=session_key).keys())
        
        if app not in getapp:
            print('App ' + app + ' not found in splunk')
            sys.exit(1)
        return True
    except:
        raise

# Retrieve knowledge objects for user
def retrieve_content(session_key, ko_name, owner, file=None, filter=None):
    try:
        # For Saved Searches
        if ko_name == 'macro':
            config_endpoint = '/servicesNS/-/-/configs/conf-macros'
        # For Saved Searches
        if ko_name == 'savedsearch':
            config_endpoint = '/servicesNS/-/-/saved/searches'
        # For Dashboards
        elif ko_name == 'dashboard':
            config_endpoint = '/servicesNS/-/-/data/ui/views'
        # For Lookup Definitions
        elif ko_name == 'lookupdef':
            config_endpoint = '/servicesNS/-/-/data/transforms/lookups'
        # For Lookup Files
        elif ko_name == 'lookupfile':
            config_endpoint = '/servicesNS/-/-/data/lookup-table-files'
        # For Tags
        elif ko_name == 'tag':
            config_endpoint = '/servicesNS/-/-/saved/fvtags'
        # For Field Extractions	
        elif ko_name == 'field_extraction':
            config_endpoint = '/servicesNS/-/-/data/props/extractions'
        # For Panels
        elif ko_name == 'panel':
            config_endpoint = '/servicesNS/-/-/data/ui/panels'
        # For Field Transformations
        elif ko_name == 'field_transformation':
            config_endpoint = '/servicesNS/-/-/data/transforms/extractions'
        # For Workflow Actions
        elif ko_name == 'e':
            config_endpoint = '/servicesNS/-/-/data/ui/workflow-actions'
        # For Datamodels
        elif ko_name == 'datamodel':
            config_endpoint = '/servicesNS/-/-/data/models'
        # For Eventtypes
        elif ko_name == 'eventtype':
            config_endpoint = '/servicesNS/-/-/saved/eventtypes'
        # For Fieldaliases
        elif ko_name == 'fieldalias':
            config_endpoint = '/servicesNS/-/-/data/props/fieldaliases'
        # For transforms_extract
        elif ko_name == 'transforms_extract':
            config_endpoint = '/servicesNS/-/-/data/transforms/extractions'
        # For commands
        elif ko_name == 'command':
            config_endpoint = '/servicesNS/-/-/data/commands'
        # For Panel
        elif ko_name == 'panel':
            config_endpoint = '/servicesNS/-/-/data/ui/panels'
        # For Collection
        elif ko_name == 'collection':
            config_endpoint = '/servicesNS/-/-/storage/collections/config'
        # For Modalerts
        elif ko_name == 'modalert':
            config_endpoint = '/servicesNS/-/-/data/ui/alerts'
        # For Navigations
        elif ko_name == 'nav':
            config_endpoint = '/servicesNS/-/-/data/ui/nav'

        # Get Argument
        if ko_name == 'savedsearch':
            get_argument = {'output_mode': 'json', 'count': 0, 'add_orphan_field': 'yes', 'f': 'title', 'f': 'orphan'}
        else:
            get_argument = {'output_mode': 'json', 'count': 0, 'f': 'title'}
        
        if filter:
            get_argument = json.loads(json.dumps(get_argument))
            get_argument['search'] = str(filter)
        (response, content) = rest.simpleRequest(config_endpoint, session_key, getargs=get_argument, timeout=300)
    except:
        raise
        
    ko_config = json.loads(content)
    ko_details.append(['App Name', 'Author Name', 'Title', 'Type of KO', 'List URL', 'Permission', 'Read Perm', 'Write Perm', 'Orphan'])
    ko_details.append(['===========', '===========', '===========', '===========', '===========', '===========', '===========', '===========', '==========='])
    
    # Search knowledge objects for user from all users output and append into ko_details list.
    for i in range(len(ko_config['entry'])):
        if owner:

            if 'author' in ko_config['entry'][i]:
                author_name = ko_config['entry'][i]['author']
            else:
                author_name = owner

            if author_name == owner :
                ko_title = ko_config['entry'][i]['name']
                sharing = ko_config['entry'][i]['acl']['sharing']
                app_name = ko_config['entry'][i]['acl']['app']
                list_url = ko_config['entry'][i]['links']['list']
                if ko_name == 'savedsearch':
                    orphan = str(ko_config['entry'][i]['content']['orphan'])
                else:
                    orphan = 'N/A'
                
                if ko_config['entry'][i]['acl']['perms'] is not None:
                    if 'read' in ko_config['entry'][i]['acl']['perms']:
                        read_perm = ','.join(ko_config['entry'][i]['acl']['perms']['read'])
                    else:
                        read_perm = 'None'
                    
                    if 'write' in ko_config['entry'][i]['acl']['perms']:
                        write_perm = ','.join(ko_config['entry'][i]['acl']['perms']['write'])
                    else:
                        write_perm = 'None'
                else:
                    read_perm = 'None'
                    write_perm = 'None'
                
                if not ((ko_name == 'field_extraction' and sharing == 'user') or (ko_name == 'tag' and sharing == 'user')): 
                    ko_details.append([app_name, author_name, ko_title, ko_name, list_url, sharing, read_perm, write_perm, orphan])

    
        if file:
            with open(file, encoding='utf-8') as read_f:
                f_content = read_f.read().splitlines()
            for f_title in f_content:
                ko_title = ko_config['entry'][i]['name']
                if f_title == ko_title:
                    author_name = ko_config['entry'][i]['author']
                    sharing = ko_config['entry'][i]['acl']['sharing']
                    app_name = ko_config['entry'][i]['acl']['app']
                    list_url = ko_config['entry'][i]['links']['list']
                    if ko_name == 'savedsearch':
                        orphan = str(ko_config['entry'][i]['content']['orphan'])
                    else:
                        orphan = 'N/A'
                    
                    if ko_config['entry'][i]['acl']['perms'] is not None:
                        if 'read' in ko_config['entry'][i]['acl']['perms']:
                            read_perm = ','.join(ko_config['entry'][i]['acl']['perms']['read'])
                        else:
                            read_perm = 'None'
                    
                        if 'write' in ko_config['entry'][i]['acl']['perms']:
                            write_perm = ','.join(ko_config['entry'][i]['acl']['perms']['write'])
                        else:
                            write_perm = 'None'
                    else:
                        read_perm = 'None'
                        write_perm = 'None'
                
                    if not ((ko_name == 'field_extraction' and sharing == 'user') or (ko_name == 'tag' and sharing == 'user')): 
                        ko_details.append([app_name, author_name, ko_title, ko_name, list_url, sharing, read_perm, write_perm, orphan])
    
    # Check if user have any knowledge object or not and then print message and exit the script if no knowledge objects found.
    if len(ko_details) <= 2 :
        print('No ' + ko_name + ' found')
        sys.exit(1)
    else:
        print('Total ' + str(len(ko_details)-2) + ' ' + ko_name + ' found')
        col_array = []

        # Searching maximum length for every row in each column and adding 2 for padding & store them into col_array list
        for col in zip(*ko_details):
            col_width = max(len(string) for string in col) + 2
            col_array.append(col_width)
        
        # Print ko_details list and inogre 4th column "List URL" while printing
        for row in ko_details:
            j = 0
            print('')
            for index, string in enumerate(row):
                if index != 4:
                    print(''.join(string.ljust(col_array[j])), end=' ')
                j = j + 1
                
        print('\n')
        return ko_details, col_array

def contruct_platform_roles(p):
  platform = []
  r_std = []
  r_pwr = []
  # split platform if multiple
  if ',' in p:
    platform = p.split(',')
  if len(platform) == 0:
    platform.append(p)
  
  for p in platform:
    platform_standard_role = 'logit_{}_generic_standard'.format(p)
    r_std.append(platform_standard_role)
    platform_power_role = 'logit_{}_generic_power'.format(p)
    r_pwr.append(platform_power_role)
    isa_platform_standard_role = 'logit_isa_{}_generic_standard'.format(p)
    r_std.append(isa_platform_standard_role)
    isa_platform_power_role = 'logit_isa_{}_generic_power'.format(p)
    r_pwr.append(isa_platform_power_role)  
  
  return r_std, r_pwr

# Change permission of knowledge objects 
def change_permission(session_key, ko_name, old_owner, new_owner, file=None, filter=None, new_sharing=None, new_readperm=None, platform=None):
    try:
        # Retrieve knowledge objects
        (ko_details, col_array) = retrieve_content(session_key, ko_name, old_owner, file, filter)
        user_input = input('Do you want to change now?[y/n] ').lower()
        
        if user_input == 'y':
            col_array.append(50)
            ko_details[0].append('New Read Perm')
            ko_details[1].append('========')          
            col_array.append(50)
            ko_details[0].append('New Write Perm')
            ko_details[1].append('========')          
            col_array.append(12)
            # Append new column "Status" in ko_details list. 
            ko_details[0].append('Status')
            ko_details[1].append('========')
            
            (roles_standard,roles_power) = contruct_platform_roles(platform)
            
            # Print first 2 array from ko_details and ignore 4th column "List URL" while printing.
            for row in ko_details[:2]:
                j = 0
                print('')
                for index, string in enumerate(row):
                    if index < 4 or index > 7 :
                        print(''.join(string.ljust(col_array[j])), end=' ')
                    j = j + 1

            # Change permission and print column starting from 3rd array and ignore 4th column "List URL" while printing.
            for row in ko_details[2:]:
                data_index = ko_details.index(row)
                #app_name = row[0]
                author_name = row[1]
                #ko_title = row[2]
                list_url = row[4]
                sharing = row[5]
                old_read_perm = row[6]
                old_write_perm = row[7]
                orphan = row[8]

                print('lenght of old_read_perm:{}'.format(len(old_read_perm)))
                if old_read_perm == 'None':
                  # new_read_perm = '{},{},{},{}'.format(platform_standard_role, platform_power_role, isa_platform_standard_role, isa_platform_power_role)
                  new_read_perm=','.join(roles_standard) +','+ ','.join(roles_power)
                elif old_read_perm == '*':
                  new_read_perm = old_read_perm
                else:
                  for role in roles_standard:
                    if(role not in old_read_perm):
                      old_read_perm = old_read_perm + ',{}'.format(role)
                  for role in roles_power:
                    if(role not in old_read_perm):
                      old_read_perm = old_read_perm + ',{}'.format(role)
                  new_read_perm = old_read_perm

                if old_write_perm == 'None' or old_write_perm == '*':
                  # new_write_perm = '{},{}'.format(platform_power_role, isa_platform_power_role)
                  new_write_perm = ','.join(roles_power)
                else:
                  for role in roles_power:
                    if(role not in old_write_perm):
                      old_write_perm = old_write_perm + ',{}'.format(role)
                  new_write_perm = old_write_perm
              
                ko_details[data_index].append(new_read_perm)
                ko_details[data_index].append(new_write_perm)

                post_argument = {'sharing': sharing, 'owner': author_name, 'perms.read': new_read_perm, 'perms.write': new_write_perm}
                    
                
                try:
                    if ko_name == 'savedsearch' and orphan == 'True':
                        list_url = re.sub(r'^((?:[^\/]*\/){2})(?:[^\/]*)(\/.*)', r'\1nobody\2', list_url)
                        post_argument = json.loads(json.dumps(post_argument))
                        post_argument['add_orphan_field'] = 'yes'
                    acl_url = list_url + '/acl'
                    rest.simpleRequest(acl_url, sessionKey=session_key, postargs=post_argument, method='POST', raiseAllErrors=True, timeout=300)
                    # Fetching index for value in list and append value
                    data_index = ko_details.index(row)
                    ko_details[data_index].append('Changed')
                    ko_array_value = ko_details[data_index]
                    j = 0
                    print('')
                    
                    for index, string in enumerate(ko_array_value):
                        if index < 4 or index > 7 :
                            print(''.join(string.ljust(col_array[j])), end=' ')
                        j = j + 1
                except:
                    data_index = ko_details.index(row)
                    ko_details[data_index].append('Failed')
                    ko_array_value = ko_details[data_index]
                    j = 0
                    print('')
                    
                    for index, string in enumerate(ko_array_value):
                        if index < 4 or index > 7 :
                            print(''.join(string.ljust(col_array[j])), end=' ')
                        j = j + 1
                    raise
            print('\n')
        elif user_input == 'n':
            sys.exit(1)
        else:
            print ("Please respond with 'y' or 'n'")
    except:
        raise
        

# Move knowledge objects from one app to another app
def move_app(session_key, ko_name, owner, file=None, filter=None, new_appname=None):
    try:
        # Retrieve knowledge objects
        (ko_details, col_array) = retrieve_content(session_key, ko_name, owner, file, filter)
        user_input = input('Do you want to move now?[y/n] ').lower()
        
        if user_input == 'y':
            col_array.append(9)
            # Append new column "Status" in ko_details list. 
            ko_details[0].append('Status')
            ko_details[1].append('========')
            
            # Print first 2 array from ko_details and ignore 4th column "List URL" while printing.
            for row in ko_details[:2]:
                j = 0
                print('')
                for index, string in enumerate(row):
                    if index != 4:
                        print(''.join(string.ljust(col_array[j])), end=' ')
                    j = j + 1
			
            # Move app and print column starting from 3rd array and ignore 4th column "List URL" while printing.
            for row in ko_details[2:]:
                #app_name = row[0]
                author_name = row[1]
                #ko_title = row[2]
                list_url = row[4]
                sharing = row[5]
                
                mv_url = list_url + '/move'
                if new_appname and sharing == 'user':
                    post_argument = {'user': author_name, 'app': new_appname}
                else:
                    post_argument = {'user': 'nobody', 'app': new_appname}
                
                try:
                    rest.simpleRequest(mv_url, sessionKey=session_key, postargs=post_argument, method='POST', raiseAllErrors=True)
                    # Fetching index for value in list and append value
                    data_index = ko_details.index(row)
                    ko_details[data_index].append('Moved')
                    ko_array_value = ko_details[data_index]
                    j = 0
                    print('')
                    
                    for index, string in enumerate(ko_array_value):
                        if index != 4:
                            print(''.join(string.ljust(col_array[j])), end=' ')
                        j = j + 1
                except:
                    data_index = ko_details.index(row)
                    ko_details[data_index].append('Failed')
                    ko_array_value = ko_details[data_index]
                    j = 0
                    print('')
                    
                    for index, string in enumerate(ko_array_value):
                        if index != 4:
                            print(''.join(string.ljust(col_array[j])), end=' ')
                        j = j + 1
                    # raise
            print('\n')
        elif user_input == 'n':
            sys.exit(1)
        else:
            print ("Please respond with 'y' or 'n'")
    except:
        raise

def main():
    # Call argument_parser function and store returned value into ko_value variable
    ko_value = argument_parser()

    if ko_value[2]!="":
        mergeHostPath(ko_value[2], True)

    session_key = user_check(ko_value)
    
    ko_name = ko_value[1]
    filter = ko_value[3]
    owner = ko_value[4]
    file = ko_value[5]

    # Retrieve knowledge objects
    if ko_value[0] == 'list':
        retrieve_content(session_key, ko_name, owner, file, filter)
    elif ko_value[0] == 'change':
        new_owner = ko_value[6]
        sharing = ko_value[7]
        read_perm = ko_value[8]
        platform = ko_value[9]

        # if read_perm:
        #     if ',' in read_perm:
        #         r_perm = read_perm.split(',')
        #     else:
        #         r_perm = read_perm.split(' ')

        # if write_perm:
        #     if ',' in write_perm:
        #         w_perm = write_perm.split(',')
        #     else:
        #         w_perm = write_perm.split(' ')

        # Check whether role exist or not for Read and Write permission
        # if read_perm and write_perm:
        #     for readrole in r_perm:
        #         if readrole != '*':
        #             role_check(readrole)
        #         else:
        #             if len(r_perm) > 1:
        #                 print ('You can\'t supply \'*\' with any other role in read permission')
        #                 sys.exit(1)
        #     for writerole in w_perm:
        #         if writerole != '*':
        #             role_check(writerole)
        #         else:
        #             if len(w_perm) > 1:
        #                 print ('You can\'t supply \'*\' with any other role in write permission')
        #                 sys.exit(1)
        # elif read_perm:
        #     for readrole in r_perm:
        #         if readrole != '*':
        #             role_check(readrole)
        #         else:
        #             if len(r_perm) > 1:
        #                 print ('You can\'t supply \'*\' with any other role in read permission')
        #                 sys.exit(1)
        # elif write_perm:
        #     for writerole in w_perm:
        #         if writerole != '*':
        #             role_check(writerole)
        #         else:
        #             if len(w_perm) > 1:
        #                 print ('You can\'t supply \'*\' with any other role in write permission')
        #                 sys.exit(1)
                
        change_permission(session_key, ko_name, owner, new_owner, file, filter, sharing, read_perm, platform)
    elif ko_value[0] == 'move':
        appname = ko_value[6]
        if appname:
            app_check(appname, session_key)
        
        move_app(session_key, ko_name, owner, file, filter, appname)
		
if __name__ == '__main__':
    try:
        main()
    except:
        raise
