#!/bin/sh

DIR="attack-csv-data"
for VER in $(ls $DIR)
do
  INDEX="$DIR/$VER/index.html"
  echo "making $INDEX..."
  cat > $INDEX << EOF
<!DOCTYPE html>
<html>
  <head>
    <title>ATT&CK $VER CSV Data Storage</title>
  </head>
  <body>

    <h1>ATT&CK $VER CSV Data Storage</h1>

    <h2>CSV files <u><i>WITH</i></u> ATT&CK ID</h2>

    <table border="1">
      <tr>
        <th width="250">SDO</th>
        <th width="400">CSV</th>
      </tr>
EOF
  for FILE in $(/usr/bin/env ls "$DIR/$VER/" | /usr/bin/env grep -e "-w-id.csv")
  do
    cat >> $INDEX << EOF
      <tr>
        <td>$(/usr/bin/env basename $FILE -w-id.csv)</td>
        <td><a href="$FILE">$FILE</a></td>
      </tr>
EOF
  done
  cat >> $INDEX << EOF
    </table>

    <h2>CSV files <u><i>WITHOUT</i></u> ATT&CK ID</h2>

    <table border="1">
      <tr>
        <th width="250">SDO</th>
        <th width="400">CSV</th>
      </tr>
EOF
  for FILE in $(/usr/bin/env ls "$DIR/$VER/" | /usr/bin/env grep ".csv" | /usr/bin/env grep -v -e "-w-id.csv")
  do
    cat >> $INDEX << EOF
      <tr>
        <td>$(/usr/bin/env basename $FILE .csv)</td>
        <td><a href="$FILE">$FILE</a></td>
      </tr>
EOF
  done
  cat >> $INDEX << EOF
    </table>

  </body>
</html>
EOF
done
