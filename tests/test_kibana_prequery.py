"""Regression tests for the Kibana prequery tool (Track 2).

Run from the repo root:  pytest tests/test_kibana_prequery.py

A local HTTP server stands in for Elasticsearch and only "has" the data
streams Elastic really creates, so a query whose index pattern matches
nothing shows up the same way it would on the live instance.

Tests marked xfail track open items in the prequery set. They keep CI
green while the items are open and start passing once each one is done.
"""
import fnmatch
import importlib.util
import json
import os
import sys
import threading
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUERIES_DIR = os.path.join(ROOT, 'kibana_queries')
FIXTURES = os.path.join(ROOT, 'tests', 'fixtures', 'kibana_alerts')

REQUIRED = ['alert_parser.py', 'query_builder.py', 'rule_queries.py',
            'kibana_connector.py', 'results_formatter.py']
if not all(os.path.exists(os.path.join(QUERIES_DIR, f)) for f in REQUIRED):
    pytest.skip('kibana_queries modules are not all in the repo yet',
                allow_module_level=True)

sys.path.insert(0, QUERIES_DIR)
from alert_parser import AlertParser
from kibana_connector import KibanaConnector
from results_formatter import ResultsFormatter
from rule_queries import RuleQueries

REAL_DATA_STREAMS = [
    '.alerts-security.alerts-default',
    'logs-endpoint.events.process-default',
    'logs-endpoint.events.network-default',
    'logs-endpoint.events.file-default',
    'logs-endpoint.events.api-default',
    'logs-windows.powershell_operational-default',
    'logs-system.security-default',
    'logs-system.auth-default',
]
PUBLIC_IP = '185.220.101.5'


def load(name):
    with open(os.path.join(FIXTURES, f'{name}.json'), encoding='utf-8') as f:
        return json.load(f)


def matches_real_data(index_pattern):
    return any(fnmatch.fnmatch(ds, p.strip())
               for p in index_pattern.split(',') for ds in REAL_DATA_STREAMS)


# ------------------------------------------------- fake Elasticsearch
class FakeElasticsearch(BaseHTTPRequestHandler):
    requests_seen = []

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = json.loads(self.rfile.read(length))
        FakeElasticsearch.requests_seen.append(
            (self.path, self.headers.get('Authorization'), body))
        index = self.path.split('/')[1].split('?')[0].replace('%2C', ',')
        found = matches_real_data(index)
        hits = []
        if found:
            hits = [{'_source': {
                '@timestamp': '2026-11-06T18:05:20Z',
                'host': {'name': 'TEST-WIN10'},
                'process': {'name': 'cmd.exe',
                            'command_line': 'cmd.exe /c whoami'},
                'destination': {'ip': PUBLIC_IP, 'port': 4444},
            }}]
        payload = json.dumps({
            '_shards': {'total': 1 if found else 0},
            'hits': {'total': {'value': len(hits)}, 'hits': hits},
        }).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_es(monkeypatch):
    server = HTTPServer(('127.0.0.1', 0), FakeElasticsearch)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    FakeElasticsearch.requests_seen = []
    monkeypatch.setenv('ES_URL', f'http://127.0.0.1:{server.server_port}')
    monkeypatch.setenv('ES_API_KEY', 'test-key')
    yield server
    server.shutdown()
    server.server_close()


# ------------------------------------------- connector and formatter
def test_connector_needs_an_elasticsearch_url():
    with pytest.raises(ValueError):
        KibanaConnector(kibana_url='https://kibana.example.edu')
    derived = KibanaConnector(kibana_url='http://10.0.0.5:5601')
    assert derived.es_url == 'http://10.0.0.5:9200'
    direct = KibanaConnector(es_url='https://10.0.0.5:9200/')
    assert direct.es_url == 'https://10.0.0.5:9200'


def test_connector_flags_patterns_that_match_no_data(fake_es):
    connector = ResultsFormatter.from_env().connector
    missing = connector.execute_query(
        {'query_name': 'x', 'kql': 'host.name: "a"',
         'index_pattern': 'logs-nothing-*'})
    present = connector.execute_query(
        {'query_name': 'y', 'kql': 'host.name: "a"',
         'index_pattern': 'logs-*'})
    assert 'matched no indices' in missing['warning']
    assert 'warning' not in present
    _, auth, _ = FakeElasticsearch.requests_seen[0]
    assert auth == 'ApiKey test-key'


def test_rule_names_map_to_query_sets():
    f = ResultsFormatter()
    assert f._rule_key('Potential Command Shell via NetCat') == 'netcat'
    assert f._rule_key('mimikatz') == 'mimikatz'
    assert f._rule_key(
        'Potential Privilege Escalation via Python cap_setuid') == \
        'python_privesc'
    assert f._rule_key('Some Other Rule') is None


def test_summary_reads_kibana_alert_fields():
    out = ResultsFormatter().process_alert(load('netcat'), dry_run=True)
    summary = out['alert_summary']
    assert summary['rule_name'] == 'Potential Command Shell via NetCat'
    assert summary['severity'] == 'high'
    assert summary['alert_id'] == 'sample-netcat-0001'
    assert summary['timestamp'] == '2026-11-06T18:05:10.412Z'
    assert out['metadata']['query_set'] == 'netcat'


def test_bad_timestamp_is_reported_not_replaced_with_now():
    out = ResultsFormatter().process_alert({'rule_name': 'netcat'})
    assert 'bad alert timestamp' in out['metadata']['error']
    assert out['metadata']['executed_queries'] == 0


def test_literal_star_queries_are_skipped():
    out = ResultsFormatter().process_alert(load('cap_setuid'),
                                           dry_run=True)
    skipped = [v for v in out['query_results'].values() if 'skipped' in v]
    assert skipped and out['metadata']['executed_queries'] == 0


def test_app_alert_format_is_unwrapped():
    out = ResultsFormatter().process_alert(
        {'raw_kibana_doc': load('netcat'), 'source_ip': PUBLIC_IP},
        dry_run=True)
    assert out['metadata']['query_set'] == 'netcat'


def test_unknown_rule_uses_generic_queries():
    out = ResultsFormatter().process_alert(
        {'rule_name': 'Test Port Scan Detected', 'source_ip': PUBLIC_IP,
         'timestamp': '2026-11-07T12:45:00+00:00'}, dry_run=True)
    assert out['metadata']['query_set'] == 'generic'
    assert 'IP Connections' in out['query_results']


def test_live_run_keeps_evidence_fields_and_osint(fake_es):
    out = ResultsFormatter.from_env().process_alert(load('netcat'))
    events = [e for r in out['query_results'].values()
              for e in r.get('events', [])]
    assert events, 'queries on logs-* should return the fake event'
    assert events[0]['process.command_line'] == 'cmd.exe /c whoami'
    assert events[0]['destination.port'] == 4444
    assert out['osint_indicators']['ips'] == [PUBLIC_IP]
    assert out['warnings'], 'unmatched index patterns should be reported'


def _load_plugin():
    path = os.path.join(ROOT, 'plugins', 'kibana_prequery_plugin.py')
    spec = importlib.util.spec_from_file_location('kq_plugin', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.plugin_instance


def test_plugin_without_config_returns_error(monkeypatch):
    monkeypatch.delenv('ES_URL', raising=False)
    monkeypatch.delenv('KIBANA_URL', raising=False)
    out = _load_plugin().run({'source_ip': PUBLIC_IP})
    assert out['module'] == 'Kibana Prequery' and 'error' in out


def test_plugin_with_server_returns_verdict(fake_es):
    out = _load_plugin().run({'raw_kibana_doc': load('netcat')})
    assert out['module'] == 'Kibana Prequery'
    assert 'prequeries' in out['verdict']


# ------------------------------------------ open items in the query set
@pytest.mark.xfail(reason='open item: index patterns do not match Elastic '
                          'data stream names yet')
def test_rule_query_index_patterns_match_real_data():
    entities = {'hostname': 'h', 'username': 'u', 'destination_ip': 'd'}
    rq = RuleQueries()
    for rule in rq.rules:
        for q in rq.get_queries(rule, entities, '2026-11-06T18:00:00Z'):
            assert matches_real_data(q['index_pattern']), \
                f"{rule}: {q['query_name']} uses {q['index_pattern']}"


@pytest.mark.xfail(reason='open item: parser does not read kibana.alert.* '
                          'fields yet')
def test_parser_reads_kibana_alert_rule_name():
    meta = AlertParser().parse(load('netcat'))['metadata']
    assert meta['rule_name'] == 'Potential Command Shell via NetCat'


@pytest.mark.xfail(reason='open item: queries do not use process entity '
                          'IDs yet')
def test_netcat_queries_follow_the_alerted_process():
    out = ResultsFormatter().process_alert(load('netcat'), dry_run=True)
    kql = ' '.join(r['kql'] for r in out['query_results'].values())
    assert 'sample-entity-nc-0001' in kql


@pytest.mark.xfail(reason='open item: python_privesc queries need host.id '
                          'and process.entity_id support')
def test_python_privesc_alert_gets_runnable_queries():
    out = ResultsFormatter().process_alert(load('cap_setuid'),
                                           dry_run=True)
    assert out['metadata']['executed_queries'] == 0
    assert out['metadata']['skipped_queries'] == 0


@pytest.mark.xfail(reason='open item: time window ends 5 minutes after '
                          'the alert')
def test_subsequent_logons_window_reaches_past_the_alert():
    out = ResultsFormatter().process_alert(load('mimikatz'), dry_run=True)
    window = out['query_results']['Subsequent Authentication']['time_range']
    alert_time = datetime.fromisoformat('2026-11-06T18:20:41.906+00:00')
    end = datetime.fromisoformat(window['lte'])
    assert end - alert_time >= timedelta(hours=1)
