#!/bin/bash

MAIL_PASSWORD=$(pass pfa4@alumnes.udl.cat)
export MAIL_PASSWORD
python mail.py
