# plugins/kibana_prequery_plugin.py
"""Runs the Kibana prequeries for each alert the app receives.

Loads the modules in kibana_queries/, which deploys next to plugins/.
Needs ES_URL plus ES_API_KEY (or ES_USERNAME and ES_PASSWORD) in the
environment; without them it returns an error entry instead of failing.
"""
import os
import sys

QUERIES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'kibana_queries')


class KibanaPrequeryPlugin:
    MODULE = 'Kibana Prequery'

    def __init__(self):
        self._formatter = None

    def _get_formatter(self):
        if self._formatter is None:
            if QUERIES_DIR not in sys.path:
                sys.path.insert(0, QUERIES_DIR)
            from results_formatter import ResultsFormatter
            self._formatter = ResultsFormatter.from_env()
        return self._formatter

    def run(self, alert: dict) -> dict:
        if not (os.environ.get('ES_URL') or os.environ.get('KIBANA_URL')):
            return {'module': self.MODULE, 'error': 'ES_URL is not set'}
        try:
            result = self._get_formatter().process_alert(alert)
        except Exception as e:
            return {'module': self.MODULE, 'error': f'Prequery failed: {e}'}

        result.pop('original_alert', None)
        meta = result['metadata']
        if meta.get('error'):
            return {'module': self.MODULE, 'error': meta['error']}
        return {
            'module': self.MODULE,
            'verdict': (f"{meta['total_events']} events from "
                        f"{meta['successful_queries']} of "
                        f"{meta['executed_queries']} prequeries"),
            'query_set': meta['query_set'],
            'osint_indicators': result['osint_indicators'],
            'prequery': result,
        }


plugin_instance = KibanaPrequeryPlugin()
