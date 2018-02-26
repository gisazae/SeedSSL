FROM yotis/ubuntu1604-pfne

WORKDIR /app

ADD . /app

RUN python setup.py install

CMD semillero_seguridadssl
