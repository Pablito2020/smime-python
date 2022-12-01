<h1 align="center">
Signed Mail Messages with Python 📧🔑
</h1>

## Summary
- [Set Up](#set-up-)
- [Run](#run-)

## Set up 📦

### Create and enable a virtual environment

```
    $ pip install virtualenv
    $ python -m venv venv
    $ source venv/bin/activate
```

### Install the dependencies

```
    $ pip install -r requirements.txt
```

## Run 🏃
If you want to run the script, execute:

```
    $ python mail.py
```

The program uses some environment variables for knowing which message has to send, the password and mail of the user, etc. If you don't have this environment variables exported, the program will show the missing ones and exit. This project includes a template (run.sh) for exporting the variables and then run the mail.py script. Once you edit the run.sh file with your own variables you can run it with:

```
    $ ./run.sh
```
