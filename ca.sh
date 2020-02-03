#!/bin/sh

set -e

# create a CA

if [ $# -lt 3 ]; then
  echo "Usage: $0 SUBJ OUT-KEYFILE OUT-CERTFILE"
  echo "SUBJ is in format '/C=US/ST=NY/O=My Org/CN=server.myorg.com'"
  exit 1
fi

generate_ca() {
  local CSR=/tmp/csr-$RANDOM.json
  local SUBJ="$1"
  local KEYFILE=$2
  local CERTFILE=$3

  # make sure we have absolute paths for key/cert both ca and server
  
  # tools we need, either local or via docker
  local JQ="jq"
  if ! $(which jq > /dev/null); then
    JQ="docker run -i --rm colstrom/jq"
  fi
  local CFSSL="cfssl"
  if ! $(which cfssl > /dev/null); then
    CFSSL="docker run -i --rm cfssl/cfssl"
  fi

  local C=""
  local ORG=""
  local OU=""
  local L=""
  local ST=""
  local CN=""

  # separate the subject into CN, ORG, OU, C, L, ST
  while read -r line ; do
    key=${line%=*}
    value=${line#*=}
    case $key in
      "") ;;                            # ignore blank
      "C") C="$value" ; echo "got C $C" ;;
      "O") ORG="$value" ;;
      "OU") OU="$value" ;;
      "L") L="$value" ;;
      "ST") ST="$value" ;;
      "CN") CN="$value" ;;
      *) echo "unknown value in subject: $line" >2; exit 1 ;;
    esac
  done <<EOF
$(echo "$SUBJ" | tr '/' '\n' )
EOF


  cat > $CSR <<EOF
  {
    "CN": "$CN",
    "key": {
      "algo": "rsa",
      "size": 4096
    },
    "names": [
      {
        "C": "$C",
        "L": "$L",
        "O": "$ORG",
        "OU": "$OU",
        "ST": "$ST"
      }
    ]
  }
EOF

  # get the key and certificate
  local KEY_AND_CERT=$(cat $CSR | $CFSSL gencert -initca -)
  printf %s "$KEY_AND_CERT" | $JQ -r '.cert' > $CERTFILE
  printf %s "$KEY_AND_CERT" | $JQ -r '.key' > $KEYFILE

  # remove the temporary CSR file
  rm -f $CSR
}

generate_ca "$@"
