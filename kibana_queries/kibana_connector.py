"""Kibana Connector: runs prequeries against Elasticsearch.

Reading log events goes to Elasticsearch's _search endpoint, which is what
Kibana uses behind the scenes. The query text is sent as a query_string
with the time range as a filter.
"""
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests
from requests.auth import HTTPBasicAuth


class KibanaConnector:
    def __init__(self, kibana_url: Optional[str] = None,
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 api_key: Optional[str] = None,
                 es_url: Optional[str] = None,
                 ca_cert: Optional[str] = None,
                 timeout: int = 30):
        self.es_url = (es_url or self._derive_es_url(kibana_url)).rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})
        # Verify TLS
        self.session.verify = ca_cert or True

        if api_key:
            self.session.headers['Authorization'] = f'ApiKey {api_key}'
        elif username and password:
            self.session.auth = HTTPBasicAuth(username, password)

    @staticmethod
    def _derive_es_url(kibana_url: Optional[str]) -> str:
        """Fallback for callers that only pass the Kibana URL."""
        if kibana_url and ':5601' in kibana_url:
            return kibana_url.replace(':5601', ':9200')
        raise ValueError(
            'Set ES_URL to the Elasticsearch address (for example '
            'https://host:9200); it cannot be worked out from this '
            'Kibana URL.')

    def execute_query(self, query: Dict[str, Any]) -> Dict[str, Any]:
        result = {'query_name': query.get('query_name')}
        try:
            es_query = self._build_es_query(query)
            response = self._search(
                index_pattern=query.get('index_pattern', 'logs-*'),
                query=es_query,
                size=query.get('size', 100),
            )
            hits = response.get('hits', {})
            total = hits.get('total', 0)
            result.update({
                'success': True,
                'hits': hits.get('hits', []),
                'total': (total.get('value', 0)
                          if isinstance(total, dict) else total),
            })
            # Zero shards means the index pattern matched no data at all,
            # which is different from "searched and found nothing"
            if response.get('_shards', {}).get('total', 1) == 0:
                result['warning'] = (
                    f"index pattern {query.get('index_pattern')} "
                    "matched no indices")
        except Exception as e:  # one failed query does not stop the rest
            result.update({
                'success': False,
                'error': str(e),
                'hits': [],
                'total': 0,
            })
        return result

    def _build_es_query(self, query: Dict[str, Any]) -> Dict[str, Any]:
        kql = query.get('kql', '*')
        time_range = query.get('time_range', {})

        es_query = {'bool': {'must': [], 'filter': []}}

        if kql and kql != '*':
            es_query['bool']['must'].append({
                'query_string': {'query': kql, 'analyze_wildcard': True,
                                 'default_field': '*', 'lenient': True}
            })

        if time_range:
            es_query['bool']['filter'].append(
                {'range': {'@timestamp': time_range}})

        return es_query

    def _search(self, index_pattern: str, query: Dict[str, Any],
                size: int = 100) -> Dict[str, Any]:
        url = (f'{self.es_url}/'
               f"{quote(index_pattern, safe='*,.-_')}/_search")
        params = {}
        if any(p.startswith('.') for p in index_pattern.split(',')):
            # Kibana alert indices are hidden so wildcards must include them
            params['expand_wildcards'] = 'open,hidden'
        body = {
            'query': query,
            'size': size,
            'sort': [{'@timestamp': {'order': 'desc'}}],
        }
        response = self.session.post(url, json=body, params=params,
                                     timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def execute_multiple(self, queries: List[Dict[str, Any]]
                         ) -> List[Dict[str, Any]]:
        return [self.execute_query(q) for q in queries]
