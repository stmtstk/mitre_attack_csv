#!/usr/bin/env python3

import re
import csv
import json
import os
import requests
import sys
from collections import defaultdict
from typing import NewType, Any, List, Tuple, Dict, DefaultDict, Optional, cast

URL = "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
INPUT_CACHE = 'attack.json'
OUTPUT_DIR = './attack'

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
    assert (response.status_code == 200), "Failure fetching url"
    return response.json()


def assert_for_stix(attack: Attack) -> None:
    assert ('spec_version' in attack), "Failure reading version info in JSON file"
    assert ('objects' in attack), "Failure reading objects in JSON file"
    assert (attack['spec_version'] == '2.0'), "Unsupported STIX version"


def attack_by_type(attack: Attack) -> DefaultDict[str, Attacks]:
    atttack_by_type: DefaultDict[str, Any] = defaultdict(list)
    for objects in attack['objects']:
        if 'type' in objects:
            atttack_by_type[objects['type']].append(objects)
    return atttack_by_type


CODE = re.compile(r'<code>(?P<codeblock>.*?)</code>')
BOLD = re.compile(r'\*\*(.*?)\*\*')
LINK = re.compile(r'\[([^[]*?)\]\((.*?)\)')
HEADER = re.compile('(?:^|\n)#+([^\n]*)')
MTIL_HTML = re.compile('"https://attack.mitre.org/'
                       'techniques/(?P<technique>.*?)"')
MTIL_TEXT = re.compile('https://attack.mitre.org/' +
                       '(techniques|tactics|software)/(?P<technique>[^\])"]+)')


def minimd(s: str, fmt: str="text") -> str:
    """minature markdown"""
    if fmt == "html":
        s = CODE.sub(lambda x: '<code>{}</code>'.format(x.group('codeblock').replace('<', '&lt;')), s)
        s = BOLD.sub(r'<b>\1</b>', s)
        s = LINK.sub(r'<a href="\2">\1</a>', s)
        s = HEADER.sub(r'<b><u>\1</u></b><br/>', s)

        # rewrite links to mitre page to this one (mitre to internal link)
        s = MTIL_HTML.sub(lambda x: '"#{}"'.format(
            x.group('technique').replace('/', '.')), s)

        s = s.replace('\n', '<br/>')

    elif fmt == "text":
        # tidy headers
        s = HEADER.sub(r'# \1 #\n', s)

        # neaten code
        s = CODE.sub(lambda x: '`{}`'.format(x.group('codeblock')), s)

        # rewrite links to mitre page to plaintext
        #s = MTIL_TEXT.sub(lambda x: '{}'.format(x.group('technique').replace('/', '.')), s)
        s = MTIL_TEXT.sub(lambda x: x['technique'].replace('/', '.'), s)

        # remove <br>
        s = s.replace('<br>', '\n')

    return s


def make_header(attacks: Attacks) -> Header:
    names = dict.fromkeys(name for attack in attacks for name in attack)
    names = dict.fromkeys(['type', 'id', 'created', 'modified', *names])
    return cast(Header, tuple(names))


def get_fields(names: Header, attack: Attack) -> Attack:
    return cast(Attack, {name: attack.get(name, '') for name in names})


def encode(attack: Attack) -> Attack:
    return cast(Attack, {name: minimd(value) if name == 'description' else value
                         for name, value in attack.items()})


def save_csv(filename: str, attacks: Attacks) -> None:
    header = make_header(attacks)
    with open(filename, 'w', newline='\n') as f:
        writer = csv.DictWriter(f, header, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for attack in attacks:
            writer.writerow(encode(get_fields(header, attack)))


def main() -> None:
    print("Fetching latest enterprise-attack.json ...")
    attack = _load_attack() or fetch_attack(URL)
    assert_for_stix(attack)
    os.makedirs(f'{OUTPUT_DIR}', exist_ok=True)
    for type_, attacks in attack_by_type(attack).items():
        print(f"Generating CSV file ...({type_})")
        save_csv(f'{OUTPUT_DIR}/{type_}.csv', attacks)

if __name__ == '__main__':
    main()
