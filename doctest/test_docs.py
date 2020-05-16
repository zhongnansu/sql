import doctest
import os
import zc.customdoctests
import shutil
import json
import re
import random
import subprocess
import unittest
import click

from functools import partial
from odfe_sql_cli.esconnection import ESConnection
from odfe_sql_cli.utils import OutputSettings
from odfe_sql_cli.formatter import Formatter
from elasticsearch import Elasticsearch, helpers, ConnectionPool

ENDPOINT = "http://localhost:9200"


class DocTestConnection(ESConnection):

    def __init__(self):
        super(DocTestConnection, self).__init__(endpoint=ENDPOINT)
        self.set_connection()

        settings = OutputSettings(table_format="psql", is_vertical=False)
        self.formatter = Formatter(settings)

    def process(self, statement):
        data = self.execute_query(statement, use_console=False)
        output = self.formatter.format_output(data)
        output = "\n".join(output)

        click.echo(output)


cmd = DocTestConnection()
test_data_client = Elasticsearch([ENDPOINT], verify_certs=True)


def cli_transform(s):
    return u'cmd.process({0})'.format(repr(s.strip().rstrip(';')))


cli_parser = zc.customdoctests.DocTestParser(
    ps1='od>', comment_prefix='#', transform=cli_transform)


def set_up_accounts(test):
    set_up(test)
    load_file("accounts.json", "accounts")


def load_file(filename, index_name):
    # todo: using one client under the hood for both uploading test data and set up cli connection?
    #   cmd.client?
    filepath = "./test_data/" + filename

    # generate iterable data
    def load_json():
        with open(filepath, "r") as f:
            for line in f:
                yield json.loads(line)

    helpers.bulk(test_data_client, load_json(), stats_only=True, index=index_name)


def set_up(test):
    test.globs['cmd'] = cmd


def tear_down(test):
    # drop leftover tables after each test
    test_data_client.indices.delete(index="_all")


docsuite = partial(doctest.DocFileSuite,
                   tearDown=tear_down,
                   parser=cli_parser, # TODO: add bash parser for curl
                   optionflags=doctest.NORMALIZE_WHITESPACE | doctest.ELLIPSIS,
                   encoding='utf-8')


doctest_file = partial(os.path.join, 'docs')


def doctest_files(*items):
    return (doctest_file(item) for item in items)


class DocTests(unittest.TestSuite):

    def run(self, result, debug=False):
        super().run(result, debug)


def load_tests(loader, suite, ignore):
    tests = []

    for fn in doctest_files('dql/basics.rst'): # todo: add more rst to test shuffle
        tests.append(docsuite(fn, setUp=set_up_accounts))

    # randomize order of tests to make sure they don't depend on each other
    random.shuffle(tests)
    return DocTests(tests)
