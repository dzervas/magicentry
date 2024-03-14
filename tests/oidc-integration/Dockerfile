FROM python

RUN pip install pipenv

ENV PIPENV_VENV_IN_PROJECT=1
ADD Pipfile.lock Pipfile /usr/src/

WORKDIR /usr/src
RUN pipenv install

ADD . /usr/src

ENV DISCOVERY_URL=http://localhost:8080/.well-known/openid-configuration \
	CLIENT_ID=my_client \
	CLIENT_SECRET=my_secret \
	REDIRECT_URI=http://localhost:8081/redirect_uri

CMD [ "pipenv", "run", "python", "tester.py" ]
