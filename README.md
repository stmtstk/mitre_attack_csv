# mitre_attack_csv

The script (mitre_attack_csv.py) extracts all types of SDOs (STIX Domain Objects) and SROs (STIX Relationship Objects), including STIX extensions, from the latest or the specified version of ATT&CK STIX JSON file and converts and saves them into CSV files for each SDO type and one for SRO. 
You can find the resulting CSV files for the different versions of ATT&CK in the "attack-csv" directory.
- Run the script with --attack_id to include "mitre-attack-id" column (values are taken from external_id of source_name="mitre-attack" external_reference)
- Run the script with --attack_version VERSION to specify the ATT&CK version to use
- Run the script with -h to see its help message

