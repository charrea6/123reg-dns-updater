import argparse
import dataclasses

import requests
import configparser

@dataclasses.dataclass
class Config:
    username: str = ""
    password: str = ""
    domains: dict[str, list[str]] = dataclasses.field(default_factory=dict)


def load_config(filename):
    parser = configparser.ConfigParser()
    parser.read(filename)
    config = Config()
    config.username = parser.get("account", "username")
    config.password = parser.get("account", "password")
    domains = parser.get("account", "domains")
    if domains:
        for domain in domains.split(","):
            subdomains = parser.get(domain, "subdomains")
            if subdomains:
                config.domains[domain] = subdomains.split()
    return config


def get_external_ip():
    resp = requests.get("https://api.ipify.org?format=json")
    return resp.json()['ip']


class API:
    def __init__(self):
        self.session = requests.Session()

    def login(self, username, password):
        resp = self.session.post("https://sso.123-reg.co.uk/v1/api/idp/login", json={
                        "password": password,
                        "API_HOST": "123-reg.co.uk",
                        "include_cookies": True,
                        "username": username,
                        "include_cdt": True,
                        "remember_me": True,
                    })
        resp.raise_for_status()

    def get_dns(self, domain):
        resp = self.session.get("https://www.123-reg.co.uk/secure/cpanel/manage-dns/get_dns", params={"domain": domain})
        resp.raise_for_status()
        data = resp.json()['json']
        if data.get('is_success', False):
            return data['dns']
        raise RuntimeError("Failed to get DNS for domain")

    def _get_csrf(self, domain):
        resp = self.session.get(f"https://www.123-reg.co.uk/secure/cpanel/manage-dns?domain={domain}")
        resp.raise_for_status()
        token_pattern = '<input type="hidden" name="X-CSRF-Token" value="'
        csrf_start = resp.text.find(token_pattern)
        if csrf_start == -1:
            raise RuntimeError("Failed to find CSRF Token")
        csrf_start += len(token_pattern)
        csrf_end = resp.text.find('"', csrf_start + 1)
        if csrf_end == -1:
            raise RuntimeError("Failed to find CSRF Token")
        return resp.text[csrf_start:csrf_end]

    def update_dns_record(self, domain, record):
        request_data = {
            "domain": domain,
            "type": record.get("type", "A"),
            "host": record['host'],
            "data": record["data"],
            "mx_priority": record.get("mx_priority", 0),
            "ttl": 0,
            "rr_id": record['rr_id']
        }
        csrf_token = self._get_csrf(domain)
        resp = self.session.post("https://www.123-reg.co.uk/secure/cpanel/manage-dns/edit_dns_record",
                                 data=request_data, headers={"X-Csrf-Token": csrf_token})
        resp.raise_for_status()
        data = resp.json()
        if not data['json']['is_success']:
            raise RuntimeError(f"Failed to update record: {data['json']['message']}")


def parse_args():
    parser = argparse.ArgumentParser(description="Tool to update domain DNS entries within a 123-reg account.")
    parser.add_argument("-c", "--config", dest="config_file", help="Configuration file to use.")
    args = parser.parse_args()
    return args

def main():
    args = parse_args()
    config = load_config(args.config_file)
    current_ip = get_external_ip()
    print(f"External IP: {current_ip}")
    api = API()
    api.login(config.username, config.password)
    for domain, subdomains in config.domains.items():
        print(f"Checking subdomains in {domain} {subdomains}")
        dns = api.get_dns(domain)
        for record in dns['records']:
            if record["host"] in subdomains:
                if record['data'] != current_ip:
                    record['data'] = current_ip
                    api.update_dns_record(domain, record)
                    print(f'Updated {record["host"]}')


if __name__ == '__main__':
    main()
