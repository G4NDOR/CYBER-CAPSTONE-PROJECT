import json
from typing import Dict, Any

class AlertParser:
    def parse(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'metadata': self._extract_metadata(alert_data),
            'entities': self._extract_entities(alert_data),
        }

    def _extract_metadata(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'timestamp': alert.get('@timestamp') or alert.get('timestamp'),
            'rule_id': alert.get('rule', {}).get('id') or alert.get('rule_id'),
            'rule_name': alert.get('rule', {}).get('name') or alert.get('rule_name'),
            'severity': alert.get('severity') or alert.get('event', {}).get('severity'),
            'alert_id': alert.get('_id') or alert.get('alert_id'),
        }

    def _extract_entities(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        entities = {
            'source_ip': alert.get('source', {}).get('ip') or alert.get('source_ip'),
            'destination_ip': alert.get('destination', {}).get('ip') or alert.get('dest_ip'),
            'hostname': alert.get('host', {}).get('name') or alert.get('hostname') or alert.get('agent', {}).get('hostname'),
            'username': alert.get('user', {}).get('name') or alert.get('username'),
            'process_name': alert.get('process', {}).get('name') or alert.get('process_name'),
            'process_pid': alert.get('process', {}).get('pid') or alert.get('process_pid'),
            'source_port': alert.get('source', {}).get('port') or alert.get('source_port'),
            'destination_port': alert.get('destination', {}).get('port') or alert.get('dest_port'),
        }
        return {k: v for k, v in entities.items() if v is not None}
