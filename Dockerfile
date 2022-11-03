FROM python:3.10-slim

ENV PYTHONUNBUFFERED 1


RUN mkdir /src

COPY ./src /src
COPY pyproject.toml poetry.lock ./

RUN apt-get update && apt-get install -y gcc libffi-dev g++ gettext
RUN pip install "poetry"
RUN poetry config virtualenvs.create false
RUN poetry install

WORKDIR /src