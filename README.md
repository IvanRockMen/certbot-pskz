# Certbot plugin for ps.kz authorizer

![PyPI - Status](https://img.shields.io/pypi/status/certbot-pskz.svg)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/certbot-pskz.svg)

PS.KZ DNS Authenticator plugin for
[Certbot](https://certbot.eff.org/)

Installation
---------------
```sh
pip install -U certbot
pip install certbot-pskz
```

Verify:

```sh
certbot plugin --text
```

Development
-----------
Create virtualenv install the plugin (`editable` mode),
spawn ther environment and run test:
```
python3.12 -m venv env

source env/bin/activate

pip install -e .

pip install tox

tox
```

License
-------
Copyright (c) 2024
[MIT](https://github.com/IvanRockMen/certbot-pskz/blob/main/LICENSE)
