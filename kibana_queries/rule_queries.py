from typing import Dict, Any, List
from datetime import datetime, timedelta

class RuleQueries:
    def __init__(self):
        self.rules = {
            'mimikatz': self._mimikatz_queries,
            'netcat': self._netcat_queries,
            'python_privesc': self._python_privesc_queries,
        }

    def get_queries(self, rule_name: str, entities: Dict[str, Any], alert_timestamp: str, time_window_minutes: int = 15) -> List[Dict[str, Any]]:
        query_func = self.rules.get(rule_name)
        if not query_func:
            return []
        return query_func(entities, alert_timestamp, time_window_minutes)

    def _calc_time_range(self, timestamp: str, window: int) -> tuple:
        try:
            alert_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except:
            alert_time = datetime.utcnow()
        start = alert_time - timedelta(minutes=window)
        end = alert_time + timedelta(minutes=5)
        return start.isoformat(), end.isoformat()

    def _mimikatz_queries(self, entities: Dict[str, Any], timestamp: str, window: int) -> List[Dict[str, Any]]:
        start, end = self._calc_time_range(timestamp, window)
        hostname = entities.get('hostname', '*')
        username = entities.get('username', '*')

        return [
            {
                'query_name': 'PowerShell Script Blocks',
                'kql': f'host.name: "{hostname}" AND event.code: "4104" AND powershell.file.script_block_text: *',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-windows-*',
                'size': 50,
            },
            {
                'query_name': 'Process Execution Chain',
                'kql': f'host.name: "{hostname}" AND process.name: "powershell.exe"',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-endpoint-*',
                'size': 100,
            },
            {
                'query_name': 'File Activity',
                'kql': f'host.name: "{hostname}" AND event.category: "file" AND (file.extension: ("dmp" OR "kirbi" OR "pfx" OR "cer"))',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-endpoint-*',
                'size': 100,
            },
            {
                'query_name': 'Subsequent Authentication',
                'kql': f'user.name: "{username}" AND event.category: "authentication"',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-windows-*',
                'size': 100,
            },
            {
                'query_name': 'Related Security Alerts',
                'kql': f'host.name: "{hostname}" AND event.kind: "alert"',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-*',
                'size': 50,
            },
            {
                'query_name': 'LSASS Memory Access',
                'kql': f'host.name: "{hostname}" AND process.name: "lsass.exe" AND event.action: "open"',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-endpoint-*',
                'size': 50,
            },
        ]

    def _netcat_queries(self, entities: Dict[str, Any], timestamp: str, window: int) -> List[Dict[str, Any]]:
        start, end = self._calc_time_range(timestamp, window)
        hostname = entities.get('hostname', '*')
        dest_ip = entities.get('destination_ip', '*')

        return [
            {
                'query_name': 'Parent Process',
                'kql': f'host.name: "{hostname}" AND process.name: ("cmd.exe" OR "powershell.exe")',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-endpoint-*',
                'size': 100,
            },
            {
                'query_name': 'Command Arguments',
                'kql': f'host.name: "{hostname}" AND process.command_line: *',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-endpoint-*',
                'size': 100,
            },
            {
                'query_name': 'Network Connections',
                'kql': f'host.name: "{hostname}" AND event.category: "network"',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-network-*',
                'size': 200,
            },
            {
                'query_name': 'Commands Executed',
                'kql': f'host.name: "{hostname}" AND event.category: "process"',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-endpoint-*',
                'size': 100,
            },
            {
                'query_name': 'External Communication',
                'kql': f'host.name: "{hostname}" AND event.category: "network" AND NOT destination.ip: ("10.0.0.0/8" OR "172.16.0.0/12" OR "192.168.0.0/16")',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-network-*',
                'size': 100,
            },
            {
                'query_name': 'Connected Alerts',
                'kql': f'host.name: "{hostname}" AND event.kind: "alert"',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-*',
                'size': 50,
            },
        ]

    def _python_privesc_queries(self, entities: Dict[str, Any], timestamp: str, window: int) -> List[Dict[str, Any]]:
        start, end = self._calc_time_range(timestamp, window)
        hostname = entities.get('hostname', '*')
        username = entities.get('username', '*')

        return [
            {
                'query_name': 'Process Capabilities',
                'kql': f'host.name: "{hostname}" AND process.name: "python*" AND process.thread.capabilities.effective: ("CAP_SETUID" OR "CAP_SETGID")',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-endpoint-*',
                'size': 50,
            },
            {
                'query_name': 'Privilege Escalation Events',
                'kql': f'host.name: "{hostname}" AND (user.effective.id: "0" OR user.effective.name: "root")',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-endpoint-*',
                'size': 100,
            },
            {
                'query_name': 'System Commands',
                'kql': f'host.name: "{hostname}" AND user.effective.id: "0" AND event.category: "process"',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-endpoint-*',
                'size': 100,
            },
            {
                'query_name': 'User Activity Timeline',
                'kql': f'user.name: "{username}"',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-*',
                'size': 200,
            },
            {
                'query_name': 'Root File Operations',
                'kql': f'host.name: "{hostname}" AND user.effective.id: "0" AND event.category: "file"',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-endpoint-*',
                'size': 100,
            },
            {
                'query_name': 'Session and Auth Events',
                'kql': f'host.name: "{hostname}" AND event.category: "authentication"',
                'time_range': {'gte': start, 'lte': end},
                'index_pattern': 'logs-*',
                'size': 100,
            },
        ]
