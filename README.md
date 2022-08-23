# mitre_attack_csv

This repository provides ATT&CK CSV files (Enterprise ATT&CK converted to a set of CSV files) attack-csv-data/ and the script (mitre_attack_csv.py) extracts all types of SDOs (STIX Domain Objects) and SROs (STIX Relationship Objects), including STIX extensions, from the latest or the specified version of ATT&CK STIX JSON file and converts and saves them into CSV files for each SDO type and one for SRO. 
You can find the resulting CSV files for the different versions of ATT&CK in the "attack-csv" directory.
- Run the script with --attack_id to include "mitre-attack-id" column (values are taken from external_id of source_name="mitre-attack" external_reference)
- Run the script with --attack_version VERSION to specify the ATT&CK version to use
- Run the script with -h to see its help message

## Welcome to MITRE ATT&CK CSV data storage

The table below provides the links to the CSV folders corresponding to each ATT&CK version.
There are two kinds of CSV files for each SDO of each ATT&CK version, one with ATT&CK ID (like TID, Software ID, etc.) and one without.
For example, the CSV file for attack-pattern SDO of ATT&CK version 11.3 WITHOUT ATT&CK ID is [attack-csv-data/v11.3/attack-pattern.csv](attack-csv-data/v11.3/attack-pattern.csv) and WITH ATT&CK ID is [attack-csv-data/v11.3/attack-pattern-w-id.csv](attack-csv-data/v11.3/attack-pattern-w-id.csv)


|ATT&CK Version | CSV Folder|
|---|---|
|v11.3|[o](attack-csv-data/v11.3/)|
|v11.2|[o](attack-csv-data/v11.2/)|
|v11.1|[o](attack-csv-data/v11.1/)|
|v11.0|[o](attack-csv-data/v11.0/)|
|v10.1|[o](attack-csv-data/v10.1/)|
|v10.0|[o](attack-csv-data/v10.0/)|
|v9.0|[o](attack-csv-data/v9.0/)|
|v8.2|[o](attack-csv-data/v8.2/)|
|v8.1|[o](attack-csv-data/v8.1/)|
|v8.0|[o](attack-csv-data/v8.0/)|
|v7.2|[o](attack-csv-data/v7.2/)|
|v7.1|[o](attack-csv-data/v7.1/)|
|v7.0|[o](attack-csv-data/v7.0/)|
|v6.3|[o](attack-csv-data/v6.3/)|
|v6.2|[o](attack-csv-data/v6.2/)|
|v6.1|[o](attack-csv-data/v6.1/)|
|v6.0|[o](attack-csv-data/v6.0/)|
|v5.2|[o](attack-csv-data/v5.2/)|
|v5.1|[o](attack-csv-data/v5.1/)|
|v5.0|[o](attack-csv-data/v5.0/)|
|v4.0|[o](attack-csv-data/v4.0/)|
|v3.0|[o](attack-csv-data/v3.0/)|
|v2.0|[o](attack-csv-data/v2.0/)|
|v1.0|[o](attack-csv-data/v1.0/)|


This project makes use of ATT&CK®   
https://attack.mitre.org/resources/terms-of-use/
