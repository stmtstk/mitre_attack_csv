#!/usr/bin/env python3

import re
import csv
import json
import os
import argparse
import requests
import sys
from collections import defaultdict
from typing import NewType, Any, List, Tuple, Dict, DefaultDict, Optional, cast

URL_PREFIX = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-'
INPUT_CACHE = 'attack.json'
OUTPUT_DIR = './attack-csv'
DEFAULT_VERSION = '11.3'
TOOL_VERSION = '1.0.0'

options = argparse.Namespace(
    id=False,
    version=DEFAULT_VERSION,
)

Attack = NewType('Attack', Dict[str, Any])
Attacks = NewType('Attacks', List[Attack])
AttackByType = NewType('AttackByType', Dict[str, Attacks])
Header = NewType('Header', Tuple[str, ...])


def _load_attack() -> Optional[Attack]:
    try:
        with open(INPUT_CACHE) as f:
            return json.load(f)
    except:
        return None


def fetch_attack(url: str) -> Attack:
    response = requests.get(url)
    assert (response.status_code == 200), 'Failure fetching url'
    return response.json()


def assert_for_stix(attack: Attack) -> None:
    assert ('spec_version' in attack), 'Failure reading version info in JSON file'
    assert ('objects' in attack), 'Failure reading objects in JSON file'
    assert (attack['spec_version'] in ('2.0', '2.1')), 'Unsupported STIX version'


def attack_by_type(attack: Attack) -> DefaultDict[str, Attacks]:
    atttack_by_type: DefaultDict[str, Any] = defaultdict(list)
    for objects in attack['objects']:
        if 'type' in objects:
            atttack_by_type[objects['type']].append(objects)
    return atttack_by_type


CODE = re.compile(r'<code>(?P<codeblock>.*?)</code>')
BOLD = re.compile(r'\*\*(.*?)\*\*')
LINK = re.compile(r'\[([^[]*?)\]\((.*?)\)')
HEADER = re.compile(r'(?:^|\n)#+([^\n]*)')
MTIL_HTML = re.compile(r'"https://attack.mitre.org/' +
                       r'techniques/(?P<technique>.*?)"')
MTIL_TEXT = re.compile(r'https://attack.mitre.org/' +
                       r'(techniques|tactics|software)/(?P<technique>[^\])"]+)')


def minimd(s: str, fmt: str = 'text') -> str:
    """minature markdown"""
    if fmt == 'html':
        s = CODE.sub(
            lambda x: '<code>{}</code>'.format(x['codeblock'].replace('<', '&lt;')), s)
        s = BOLD.sub(r'<b>\1</b>', s)
        s = LINK.sub(r'<a href="\2">\1</a>', s)
        s = HEADER.sub(r'<b><u>\1</u></b><br/>', s)

        # rewrite links to mitre page to this one (mitre to internal link)
        s = MTIL_HTML.sub(lambda x: '"#{}"'.format(x['technique'].replace('/', '.')), s)

        s = s.replace('\n', '<br/>')

    elif fmt == 'text':
        # tidy headers
        s = HEADER.sub(r'# \1 #\n', s)

        # neaten code
        s = CODE.sub(lambda x: '`{}`'.format(x['codeblock']), s)

        # rewrite links to mitre page to plaintext
        s = MTIL_TEXT.sub(lambda x: x['technique'].replace('/', '.'), s)

        # remove <br>
        s = s.replace('<br>', '\n')

    return s


def make_header(attacks: Attacks) -> Header:
    common_header = ['type', 'id', 'created', 'modified']
    if options.attack_id:
        common_header.append('mitre_attack_id')
    names = dict.fromkeys(name for attack in attacks for name in attack)
    names = dict.fromkeys([*common_header, *names])
    return cast(Header, tuple(names))


def get_fields(names: Header, attack: Attack) -> Attack:
    fields = {name: attack.get(name, '') for name in names}
    if options.attack_id and 'external_references' in attack:
        for r in attack['external_references']:
            if r.get('source_name') == 'mitre-attack':
                fields['mitre_attack_id'] = r['external_id']
    return cast(Attack, fields)


def encode(attack: Attack) -> Attack:
    encoded_attack = {name: minimd(value) if name == 'description' else value
                      for name, value in attack.items()}
    return cast(Attack, encoded_attack)


def save_csv(filename: str, attacks: Attacks) -> None:
    header = make_header(attacks)
    with open(filename, 'w', newline='\n') as f:
        writer = csv.DictWriter(f, header, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for attack in attacks:
            writer.writerow(encode(get_fields(header, attack)))


def main() -> None:
    print(f'Fetching ATT&CK v.{options.attack_version} STIX file ...')
    url = f'{URL_PREFIX}{options.attack_version}.json'
    attack = _load_attack() or fetch_attack(url)
    assert_for_stix(attack)
    os.makedirs(f'{OUTPUT_DIR}/v{options.attack_version}', exist_ok=True)
    for type_, attacks in attack_by_type(attack).items():
        print(f'Generating CSV file ...({type_})')
        csv_filename = type_
        if options.attack_id:
            csv_filename = f'{csv_filename}-w-id'
        save_csv(f'{OUTPUT_DIR}/v{options.attack_version}/{csv_filename}.csv', attacks)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Produce SDO/SRO CSV files from ATT&CK STIX')
    parser.add_argument('--attack_id', action='store_true',
                        help='add mitre_attack_id column')
    parser.add_argument('--attack_version', default=DEFAULT_VERSION,
                        help='specify ATT&CK version to use')
    parser.add_argument('--version', '-V', action='version', version=os.path.basename(__file__) + ' version ' + TOOL_VERSION,
                        help='show version and exit')
    return parser.parse_args()


if __name__ == '__main__':
    options = parse_args()
    main()
