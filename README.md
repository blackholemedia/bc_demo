# Bitcoin with python


[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

This is the python implementation of bitcoin .

## Table of Contents

- [Security](#security)
- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [API](#api)
- [Contributing](#contributing)
- [License](#license)
- [TODO](#todo)

## Security

left blank

## Background

In order to explore the mechanism of bitcoin, I create this project with python.**You will know how bitcoin work by this project** 

Reference: [Going the distance](https://jeiwan.net/)

## Install

Just clone the repo. You need to setup python3 environment first. And redis is necessary.

```shell
git clone https://github.com/blackholemedia/bc_demo.git
pip install -r requirements.txt
# install redis in opensuse 
zypper install redis-server
```

## Usage

You need to start redis locally.  

Start from cli, the entry is base.py, just like this `python base.py -p`. Here are the options:

```shell
-p --print: print block chain
-c --create_wallet: create a wallet
-s --show_wallets: show all wallets
-b --balance: get balance of provided address
-f --from address1 -t --to address2 -a --amount 8: transfer currency
```



## API

left blank

## More optional sections

## Contributing

See contributors of this repo.

PRs accepted.

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.


## License

left blank  
## TODO  
Consensus implementation  
