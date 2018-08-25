-include /code/containers/s2ipythonlibrary/Makefile

clean:
	find . -name \*.pyc -delete
	find . -name __pycache__ -delete
	rm -rf dist/

test_unit:
	python -3 -m pytest test_all.py
	python3 -bb -m pytest test_all.py

lint:
	flake8 .

test: test_unit lint
