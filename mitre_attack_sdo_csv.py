#!/usr/bin/python3

import re
import csv
import json
import requests
import sys


# tmp_file = 'cache.json'


def _get_input_json():
    return _get_input_json_from_web()
    # return _get_input_json_from_cache_file()


def _get_input_json_from_web():
    print("Fetching latest enterprise-attack.json ...")
    url = "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
    d = requests.get(url)
    assert (d.status_code == 200), "Failure fetching url"
    print("Parsing file ...")
    return d.json()


def _get_input_json_from_cache_file():
    print("Fetching latest enterprise-attack.json from cache file...")
    with open(tmp_file, 'r') as fp:
        j = json.load(fp)
    return j


def _assert_input_json(j):
    assert ('spec_version' in j), "Failure reading version info in JSON file"
    assert ('objects' in j), "Failure reading objects in JSON file"
    assert (j['spec_version'] == '2.0'), "Unsupported STIX version"


def _get_sdo_by_type(j):
    d = {}
    for o_ in j['objects']:
        if 'type' not in o_:
            continue
        type_ = o_['type']
        if type_ in d:
            d[type_].append(o_)
        else:
            d[type_] = [o_]
    return d


def _get_header(objects):
    header = ['type', 'id', 'created', 'modified']
    for o_ in objects:
        for key in o_.keys():
            if key not in header:
                header.append(key)
    return header


def _get_record(key, o_):
    if key not in o_:
        return ''
    v = o_[key]
    if type(v) == 'str':
        return v
    else:
        return str(v)


# minature markdown
def _minimd(s, fmt="text"):

    code = re.compile('<code>(?P<codeblock>.*?)</code>')

    bold = re.compile('\*\*(.*?)\*\*')
    link = re.compile('\[([^[]*?)\]\((.*?)\)')
    header = re.compile('(?:^|\n)#+([^\n]*)')

    if fmt == "html":
        s = code.sub(
            lambda x: '<code>{}</code>'.format(x.group('codeblock').replace('<', '&lt;')), s)
        s = bold.sub(r'<b>\1</b>', s)
        s = link.sub(r'<a href="\2">\1</a>', s)
        s = header.sub(r'<b><u>\1</u></b><br/>', s)

        # rewrite links to mitre page to this one (mitre to internal link)
        mtil = re.compile(
            '"https://attack.mitre.org/techniques/(?P<technique>.*?)"')
        s = mtil.sub(lambda x: '"#{}"'.format(
            x.group('technique').replace('/', '.')), s)

        s = s.replace('\n', '<br/>')

    elif fmt == "text":
        # tidy headers
        s = header.sub(r'# \1 #\n', s)

        # neaten code
        s = code.sub(lambda x: '`{}`'.format(x.group('codeblock')), s)

        # rewrite links to mitre page to plaintext
        mtil = re.compile(
            'https://attack.mitre.org/(techniques|tactics|software)/(?P<technique>[^\])"]+)')
        s = mtil.sub(lambda x: '{}'.format(
            x.group('technique').replace('/', '.')), s)

        # remove <br>
        s = s.replace('<br>', '\n')

    return s


def _write_csv_file(type_, objects, header):
    print("Generating CSV file ...(%s)" % (type_))
    out_file = './output/%s.csv' % (type_)
    with open(out_file, 'w', newline='\n') as out:
        writer = csv.DictWriter(
            out,
            header,
            quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for o_ in objects:
            record = {}
            for key in header:
                record[key] = _minimd(_get_record(key, o_))
            writer.writerow(record)
    return


if __name__ == '__main__':
    j = _get_input_json()
    _assert_input_json(j)
    sdo_d = _get_sdo_by_type(j)
    for type_ in sdo_d:
        objects = sdo_d[type_]
        header = _get_header(objects)
        _write_csv_file(type_, objects, header)
    sys.exit(0)
