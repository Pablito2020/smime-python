#!/bin/bash

# Set variables
MAIL_PASSWORD=$(pass pfa4@alumnes.udl.cat)
MAILFROM="pfa4@alumnes.udl.cat"
MAILTO="pfa4@alumnes.udl.cat"
NAME_SENDER="Pablo Fraile Alonso"
SUBJECT="From the CLI"
MESSAGE="This is a signed message created using the mail.py program"

# Export variables
export MAILFROM
export MAILTO
export MAIL_PASSWORD
export NAME_SENDER
export SUBJECT
export MESSAGE

python mail.py
