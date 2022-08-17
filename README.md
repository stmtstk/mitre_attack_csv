# mitre_attack_csv

The script (mitre_attack_csv.py) extracts all types of SDOs (STIX Domain Objects) and SROs, including STIX extensions, from the ATT&CK JSON file and converts and saves them into CSV files for each SDO type and one for SRO. 
You can find the resulting CSV files for the latest ATT&CK v11.3 in the "output" directory.
- Run the script with --id to include "mitre-attack-id" column (values are taken from external_id of source_name="mitre-attack" external_reference)
- Run the script with -v VERSION or --version VERSION to specify the ATT&CK version to use
- Run the scrip with -h to see its help message
