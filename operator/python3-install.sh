#!/bin/sh

PYTHON_RELEASE=${PYTHON_RELEASE:-3.7.4}
PYTHON_VERSION=${PYTHON_VERSION:-3.7}

yum install -y gcc openssl-devel bzip2-devel libffi-devel make

curl https://www.python.org/ftp/python/${PYTHON_RELEASE}/Python-${PYTHON_RELEASE}.tgz \
  -o /usr/local/src/Python-${PYTHON_RELEASE}.tgz

tar zxf /usr/local/src/Python-${PYTHON_RELEASE}.tgz -C /usr/local/src

cd /usr/local/src/Python-${PYTHON_RELEASE}
./configure --enable-optimizations
make altinstall
cd

rm -rf /usr/local/src/Python-${PYTHON_RELEASE} /usr/local/src/Python-${PYTHON_RELEASE}.tgz

ln -s python${PYTHON_VERSION} /usr/local/bin/python3
ln -s idle${PYTHON_VERSION} /usr/local/bin/idle3
ln -s pip${PYTHON_VERSION} /usr/local/bin/pip3
ln -s pydoc${PYTHON_VERSION} /usr/local/bin/pydoc3
ln -s pyvenv-${PYTHON_VERSION} /usr/local/bin/pyvenv-3
