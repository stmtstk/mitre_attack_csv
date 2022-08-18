#! /bin/sh

for VER in '11.3' '11.2' '11.1' '11.0' '10.1' '10.0' '9.0' '8.2' '8.1' '8.0' '7.2' '7.1' '7.0' \
    '6.3' '6.2' '6.1' '6.0' '5.2' '5.1' '5.0' '4.0' '3.0' '2.0' '1.0'
do
    python3 ./mitre_attack_csv.py --attack_version $VER
    python3 ./mitre_attack_csv.py --attack_version $VER --attack_id
done
