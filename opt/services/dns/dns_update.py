import requests
import json
import sys
import os 
import threading
import glob
import time
#import pathlib


class UpdateDns:
    # Default interval per each running
    MIN_INTERVAL = 60
    DEFAULT_INTERVAL = 900
    
    INTERVAL_BETWEEN_DOMAIN_UPDATE = 10
    
    parent_path = ''
    
    interval = DEFAULT_INTERVAL
    
    def __init__(self, p):
        # body of the constructor
        self.parent_path = p
    
    def load_properties(self, filepath, sep='=', comment_char='#'):
        """
        Read the file passed as parameter as a properties file.
        """
        props = {}
        with open(filepath, "rt") as f:
            for line in f:
                l = line.strip()
                if l and not l.startswith(comment_char):
                    key_value = l.split(sep)
                    key = key_value[0].strip()
                    value = sep.join(key_value[1:]).strip().strip('"') 
                    props[key] = value 
        return props
    
    
    def update(self):
        try:
            IP_API = 'https://api.ipify.org?format=json'

            resp = requests.get(IP_API)
            ip = resp.json()['ip']
            print("Got ip: {}".format(ip))

            props = self.load_properties('{}/config.properties'.format(self.parent_path))
            if 'interval' in props:
                try:
                    self.interval = int(props['interval'])
                    if self.interval < self.MIN_INTERVAL:
                        self.interval = self.MIN_INTERVAL
                except:
                    print('The interval value does not valid, use the default value ({})'.format(self.DEFAULT_INTERVAL))
            print('Interval: {}'.format(self.interval))

            # cache format: [{service,[domain,ip]}]
            # Load cache
            cache = {}
            try:
                cache_file = open('{}/cache'.format(self.parent_path))
                cache = json.load(cache_file)
            except:
                print('Cache file may not exist or has the invalid data')
            
            hostnameList = glob.glob('{}/*.host'.format(self.parent_path))
            for i in range(len(hostnameList)):
                try:
                    hostProps = self.load_properties(hostnameList[i])
                    hostType = hostProps['type']
                    login = hostProps['login']
                    password = hostProps['password']
                    domains = hostProps['domains'].split(',')
                    zone = hostProps.get('zone')
                    record_type = hostProps.get('record_type') # A, AAAA
                    proxied = hostProps.get('proxied') # True, False
                    
                    if not (hostType in cache):
                        # create
                        cache[hostType] = {}
                    
                    print(hostType, ': ', domains)
                    if hostType == 'google':
                        for j in range(len(domains)):
                            try:
                                domain = domains[j].strip()
                                if cache.get(hostType).get(domain) == ip:
                                    print('[{}] Domain: {}, ip {} does not change!'.format(hostType, domain, ip))
                                    break
                                endpoint = 'https://{}:{}@domains.google.com/nic/update?hostname={}&myip={}'.format(login, password, domain, ip)
                                response = requests.post(endpoint)
                                output = response.content.decode('utf-8')
                                if 'good' in output or 'nochg' in output:
                                    print('[{}], {} points to {}'.format(hostType, domain, ip))
                                    cache[hostType][domain] = ip
                                else:
                                    print('[{}][Error] Domain: {}, ip: {}, response: {}'.format(hostType, domain, ip, output))
                            except:
                                print('[{}][Exception] Domain: {}, ip: {}, Error: {}'.format(hostType, domain, ip, sys.exc_info()[0]))
                                
                            # For google domain, each host file is for only one domain, so don't need to sleep
                            #time.sleep(self.INTERVAL_BETWEEN_DOMAIN_UPDATE)
                            
                    elif hostType == 'cloudflare':
                        has_ip_changed = False
                        for j in range(len(domains)):
                            domain = domains[j].strip()
                            if cache.get(hostType).get(domain) != ip:
                                has_ip_changed = True
                                break
                        if has_ip_changed:
                            try:
                                base_url = 'https://api.cloudflare.com/client/v4/'
                                
                                response = requests.get(
                                    '{}zones'.format(base_url),
                                    headers={
                                        'X-Auth-Key': password,
                                        'X-Auth-Email': login
                                    }).json()
                                if response.get('success') == True:
                                    # Find zone id
                                    zone_found = False
                                    for zone_json in response.get('result'):
                                        if zone_json.get('name') == zone:
                                            zone_found = True
                                            # Process
                                            zone_id = zone_json['id']
                                            params = {}
                                            if record_type:
                                                params['type'] = record_type
                                            # Get records in zone
                                            response = requests.get(
                                                '{}zones/{}/dns_records'.format(base_url, zone_id),
                                                headers={
                                                    'X-Auth-Key': password,
                                                    'X-Auth-Email': login
                                                },
                                                params=params).json()
                                            if response.get('success') == True:
                                                #print('res: ', response)
                                                for j in range(len(domains)):
                                                    domain = domains[j].strip()
                                                    domain_found = False
                                                    for record_json in response.get('result'):
                                                        if record_json.get('name') == domain:
                                                            domain_found = True
                                                            if record_json.get('content') == ip:
                                                                print('[{}], {} already pointed to {}'.format(zone, domain, ip))
                                                                cache[hostType][domain] = ip
                                                                break
                                                            
                                                            record_id = record_json.get('id')
                                                            record_content={
                                                                    'type': 'A',
                                                                    'name': domain,
                                                                    'content': ip,
                                                                    'ttl': 1, # 1: automatic
                                                                    'proxied': False
                                                                }
                                                            if record_type:
                                                                record_content['type'] = record_type
                                                            if proxied == 'true':
                                                                record_content['proxied'] = True
                                                                
                                                            update_response = requests.put(
                                                                '{}zones/{}/dns_records/{}'.format(base_url, zone_id, record_id),
                                                                data=json.dumps(record_content),
                                                                headers={
                                                                    'X-Auth-Key': password,
                                                                    'X-Auth-Email': login,
                                                                    'Content-Type': 'application/json'
                                                                }).json()
                                                                
                                                            if update_response.get('success') == True:
                                                                print('[{}], {} points to {}'.format(zone, domain, ip))
                                                                cache[hostType][domain] = ip
                                
                                                                # Wait to execute the next domain
                                                                time.sleep(self.INTERVAL_BETWEEN_DOMAIN_UPDATE)
                                                            else:
                                                                print('[{}][Error] Domain: {}, ip: {}, response: {}'.format(zone, domain, ip, update_response.get('errors')))
                                                    if not domain_found:
                                                        print('[{}], Domain {} not found, create one?'.format(zone, domain))
                                                        # Create record
                                            else:
                                                print('[{}][Error] Domain: {} could not get records, response: {}'.format(zone, domain, output))
                                            break
                                    if not zone_found:
                                        print('[{}] Zone not found', zone)
                                else:
                                    print('[{}][Error] Could not getting zone, response: {}'.format(zone, output))
            
                            except:
                                print('Exception when updating dns for {}, ip: {}, error: {}'.format(domain, ip, sys.exc_info()[0]))
                        else:
                            print('[{}] no ip changed for all records'.format(zone))
                        
                except:
                    print('Host file {} invalid'.format(hostnameList[i]))
                                
                # Wait to execute the next host file
                time.sleep(self.INTERVAL_BETWEEN_DOMAIN_UPDATE)

            #print('Cache: ', cache)
            # save cache to file
            with open('{}/cache'.format(self.parent_path), 'w') as f:
                json.dump(cache, f)
                
            # Schedule the next running
            time.sleep(self.interval)
            self.update()
        except:
            print('The ip could not be got')
            # Schedule the next running
            time.sleep(self.MIN_INTERVAL)
            self.update()
        
        
UpdateDns(os.getcwd()).update()
