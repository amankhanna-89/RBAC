#
# Makefile for rbac
#

venv:
	virtualenv -p python3 venv
	chmod +x venv/bin/activate
	source venv/bin/activate && pip install -r requirements.txt


run:
	source venv/bin/activate && python rbac.py


test:
	source venv/bin/activate && python -m unittest test_rbac.py