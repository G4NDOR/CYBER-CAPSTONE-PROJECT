"""Results Formatter: runs the prequeries for an alert and packages them.

Flow: AlertParser -> RuleQueries or QueryBuilder -> KibanaConnector ->
formatted output. The output keeps the evidence fields analysts need and
lists the public IPs and file hashes the OSINT plugins can look up.
"""
import ipaddress
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from alert_parser import AlertParser
from kibana_connector import KibanaConnector
from query_builder import QueryBuilder
from rule_queries import RuleQueries

# Kibana rule names for the target rules, mapped to RuleQueries keys
RULE_KEYS = {
    'potential invoke-mimikatz powershell script': 'mimikatz',
    'potential command shell via netcat': 'netcat',
    'potential privilege escalation via python cap_setuid':
        'python_privesc',
}

# Fields kept for each returned event
EVENT_FIELDS = [
    '@timestamp', 'event.action', 'event.category', 'event.code',
    'host.name', 'user.name',
    'process.name', 'process.pid', 'process.command_line',
    'process.parent.name', 'process.parent.command_line',
    'powershell.file.script_block_text', 'file.path',
    'source.ip', 'source.port', 'destination.ip', 'destination.port',
    'network.direction', 'message',
]
IP_FIELDS = ['source.ip', 'destination.ip']
HASH_FIELDS = ['process.hash.sha256', 'file.hash.sha256']
LITERAL_STAR = re.compile(r':\s*"\*"')


def get_field(doc: Any, dotted: str) -> Any:
    """Read a dotted field from flat keys, nested objects, or both."""
    if not isinstance(doc, dict):
        return None
    if dotted in doc:
        return doc[dotted]
    parts = dotted.split('.')
    for i in range(len(parts) - 1, 0, -1):
        head = '.'.join(parts[:i])
        if head in doc:
            found = get_field(doc[head], '.'.join(parts[i:]))
            if found is not None:
                return found
    return None


class ResultsFormatter:
    def __init__(self, kibana_url: str = None, username: str = None,
                 password: str = None, api_key: str = None,
                 es_url: str = None, ca_cert: str = None,
                 connector: Optional[KibanaConnector] = None):
        self.parser = AlertParser()
        self.generic_queries = QueryBuilder()
        self.rule_queries = RuleQueries()
        if connector is None and (es_url or kibana_url):
            connector = KibanaConnector(kibana_url, username, password,
                                        api_key, es_url, ca_cert)
        self.connector = connector

    @classmethod
    def from_env(cls) -> 'ResultsFormatter':
        """Credentials come only from the environment"""
        return cls(kibana_url=os.environ.get('KIBANA_URL'),
                   username=os.environ.get('ES_USERNAME'),
                   password=os.environ.get('ES_PASSWORD'),
                   api_key=os.environ.get('ES_API_KEY'),
                   es_url=os.environ.get('ES_URL'),
                   ca_cert=os.environ.get('ES_CA_CERT'))

    # ------------------------------------------------------------- run
    def process_alert(self, alert_data: Dict[str, Any],
                      time_window_minutes: int = 15,
                      rule_name: str = None,
                      dry_run: bool = False) -> Dict[str, Any]:
        document = self._unwrap(alert_data)
        parsed = self.parser.parse(document)
        metadata = self._fill_metadata(parsed['metadata'], document)
        rule_key = self._rule_key(rule_name or metadata.get('rule_name'))

        try:
            self._check_timestamp(metadata.get('timestamp'))
        except ValueError as e:
            return self._format_output(alert_data, metadata, parsed,
                                       rule_key, [], [],
                                       error=f'bad alert timestamp: {e}')

        if rule_key:
            queries = self.rule_queries.get_queries(
                rule_name=rule_key,
                entities=parsed['entities'],
                alert_timestamp=metadata['timestamp'],
                time_window_minutes=time_window_minutes)
        else:
            queries = self.generic_queries.build_queries(
                entities=parsed['entities'],
                alert_timestamp=metadata['timestamp'],
                time_window_minutes=time_window_minutes)

        runnable, skipped = [], []
        for query in queries:
            if LITERAL_STAR.search(query.get('kql', '')):
                # A missing entity became "*" which only matches a literal
                # asterisk. So, running it would always return nothing.
                skipped.append({
                    'query_name': query['query_name'],
                    'kql': query['kql'],
                    'skipped': 'alert is missing a value this query needs',
                })
            else:
                runnable.append(query)

        if dry_run:
            results = [{**q, 'dry_run': True} for q in runnable]
        elif self.connector is None:
            results = [{**q, 'success': False, 'total': 0, 'hits': [],
                        'error': 'no Elasticsearch connection configured'}
                       for q in runnable]
        else:
            results = [{**q, **self.connector.execute_query(q)}
                       for q in runnable]

        return self._format_output(alert_data, metadata, parsed, rule_key,
                                   results, skipped)

    @staticmethod
    def _unwrap(alert: Dict[str, Any]) -> Dict[str, Any]:
        """Accept a Kibana alert, an Elasticsearch hit, or the app's
        simple alert with the full document in raw_kibana_doc."""
        if isinstance(alert.get('_source'), dict):
            return alert['_source']
        raw = alert.get('raw_kibana_doc')
        if isinstance(raw, dict) and raw:
            return raw
        return alert

    @staticmethod
    def _fill_metadata(metadata: Dict[str, Any],
                       document: Dict[str, Any]) -> Dict[str, Any]:
        """Kibana alerts keep rule details under kibana.alert.*, so read
        those when the parser's lookups come back empty."""
        filled = dict(metadata)
        fallbacks = {
            'timestamp': 'kibana.alert.original_time',
            'rule_id': 'kibana.alert.rule.rule_id',
            'rule_name': 'kibana.alert.rule.name',
            'severity': 'kibana.alert.severity',
            'alert_id': 'kibana.alert.uuid',
        }
        for key, field in fallbacks.items():
            value = get_field(document, field)
            if value and (not filled.get(key) or key == 'timestamp'):
                filled[key] = value
        return filled

    def _rule_key(self, rule_name: Optional[str]) -> Optional[str]:
        if not rule_name:
            return None
        name = str(rule_name).strip().lower()
        if name in self.rule_queries.rules:
            return name
        return RULE_KEYS.get(name)

    @staticmethod
    def _check_timestamp(value: Any) -> None:
        """Fail loudly instead of searching around the current time."""
        if not value:
            raise ValueError('alert has no timestamp')
        datetime.fromisoformat(str(value).replace('Z', '+00:00'))

    # ---------------------------------------------------------- output
    def _format_output(self, original, metadata, parsed, rule_key,
                       results, skipped, error=None) -> Dict[str, Any]:
        executed = [r for r in results if not r.get('dry_run')]
        output = {
            'metadata': {
                'enriched_at': datetime.now(timezone.utc).isoformat(),
                'query_set': rule_key or 'generic',
                'total_queries': len(results) + len(skipped),
                'executed_queries': len(executed),
                'skipped_queries': len(skipped),
                'successful_queries': sum(
                    1 for r in executed if r.get('success')),
                'total_events': sum(r.get('total', 0) for r in executed),
            },
            'alert_summary': {
                'rule_name': metadata.get('rule_name'),
                'rule_id': metadata.get('rule_id'),
                'alert_id': metadata.get('alert_id'),
                'timestamp': metadata.get('timestamp'),
                'severity': metadata.get('severity'),
                'entities': parsed['entities'],
            },
            'query_results': {},
            'osint_indicators': self._osint_indicators(parsed, results),
            'warnings': [r['warning'] for r in results if r.get('warning')],
            'original_alert': original,
        }
        for r in results:
            output['query_results'][r['query_name']] = self._format_result(r)
        for s in skipped:
            output['query_results'][s['query_name']] = {
                'kql': s['kql'], 'skipped': s['skipped']}
        if error:
            output['metadata']['error'] = error
        return output

    def _format_result(self, r: Dict[str, Any]) -> Dict[str, Any]:
        formatted = {
            'kql': r.get('kql'),
            'index_pattern': r.get('index_pattern'),
            'time_range': r.get('time_range'),
        }
        if r.get('dry_run'):
            formatted['dry_run'] = True
            return formatted
        formatted.update({
            'success': r.get('success', False),
            'total_events': r.get('total', 0),
            'events': self._format_events(r.get('hits', []),
                                          r.get('fields')),
            'error': r.get('error'),
        })
        if r.get('warning'):
            formatted['warning'] = r['warning']
        return formatted

    @staticmethod
    def _format_events(hits: List[Dict[str, Any]], fields=None,
                       max_events: int = 50) -> List[Dict[str, Any]]:
        events = []
        for hit in hits[:max_events]:
            source = hit.get('_source', {})
            event = {}
            for field in fields or EVENT_FIELDS:
                value = get_field(source, field)
                if value is not None:
                    event[field] = value
            events.append(event)
        return events

    @staticmethod
    def _osint_indicators(parsed, results) -> Dict[str, List[str]]:
        """Public IPs and file hashes from the alert and every result."""
        docs = [{'source': {'ip': parsed['entities'].get('source_ip')},
                 'destination': {
                     'ip': parsed['entities'].get('destination_ip')}}]
        for r in results:
            docs.extend(h.get('_source', {}) for h in r.get('hits', []))
        ips, hashes = set(), set()
        for doc in docs:
            for field in IP_FIELDS:
                value = get_field(doc, field)
                try:
                    if value and ipaddress.ip_address(value).is_global:
                        ips.add(str(value))
                except ValueError:
                    continue
            for field in HASH_FIELDS:
                value = get_field(doc, field)
                if value:
                    hashes.add(str(value).lower())
        return {'ips': sorted(ips), 'hashes': sorted(hashes)}
