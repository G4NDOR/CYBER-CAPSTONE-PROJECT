from typing import Dict, Any, List
from datetime import datetime, timedelta

class QueryBuilder:
    def build_queries(self, entities: Dict[str, Any], alert_timestamp: str, time_window_minutes: int = 15) -> List[Dict[str, Any]]:
        queries = []

        if entities.get('hostname'):
            queries.append(self._host_activity(entities['hostname'], alert_timestamp, time_window_minutes))

        if entities.get('source_ip') or entities.get('destination_ip'):
            queries.append(self._ip_connections(entities, alert_timestamp, time_window_minutes))

        if entities.get('username'):
            queries.append(self._user_activity(entities['username'], alert_timestamp, time_window_minutes))
            queries.append(self._auth_events(entities['username'], alert_timestamp, time_window_minutes))

        if entities.get('process_name'):
            queries.append(self._process_execution(entities, alert_timestamp, time_window_minutes))

        return queries

    def _calc_time_range(self, timestamp: str, window_minutes: int) -> tuple:
        try:
            alert_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except:
            alert_time = datetime.utcnow()

        start = alert_time - timedelta(minutes=window_minutes)
        end = alert_time + timedelta(minutes=5)
        return start.isoformat(), end.isoformat()

    def _host_activity(self, hostname: str, timestamp: str, window: int) -> Dict[str, Any]:
        start, end = self._calc_time_range(timestamp, window)
        return {
            'query_name': 'Host Activity',
            'kql': f'host.name: "{hostname}"',
            'time_range': {'gte': start, 'lte': end},
            'index_pattern': 'logs-*',
            'size': 500,
        }

    def _ip_connections(self, entities: Dict[str, Any], timestamp: str, window: int) -> Dict[str, Any]:
        start, end = self._calc_time_range(timestamp, window)
        conditions = []
        if entities.get('source_ip'):
            conditions.append(f'source.ip: "{entities["source_ip"]}"')
        if entities.get('destination_ip'):
            conditions.append(f'destination.ip: "{entities["destination_ip"]}"')

        return {
            'query_name': 'IP Connections',
            'kql': ' OR '.join(conditions),
            'time_range': {'gte': start, 'lte': end},
            'index_pattern': 'logs-network-*,logs-endpoint-*',
            'size': 300,
        }

    def _user_activity(self, username: str, timestamp: str, window: int) -> Dict[str, Any]:
        start, end = self._calc_time_range(timestamp, window)
        return {
            'query_name': 'User Activity',
            'kql': f'user.name: "{username}"',
            'time_range': {'gte': start, 'lte': end},
            'index_pattern': 'logs-*',
            'size': 500,
        }

    def _process_execution(self, entities: Dict[str, Any], timestamp: str, window: int) -> Dict[str, Any]:
        start, end = self._calc_time_range(timestamp, window)
        conditions = []
        if entities.get('process_name'):
            conditions.append(f'process.name: "{entities["process_name"]}"')
        if entities.get('hostname'):
            conditions.append(f'host.name: "{entities["hostname"]}"')

        kql = ' AND '.join(conditions) if len(conditions) > 1 else conditions[0]
        return {
            'query_name': 'Process Execution',
            'kql': f'({kql}) AND event.category: "process"',
            'time_range': {'gte': start, 'lte': end},
            'index_pattern': 'logs-endpoint-*,logs-windows-*',
            'size': 200,
        }

    def _auth_events(self, username: str, timestamp: str, window: int) -> Dict[str, Any]:
        start, end = self._calc_time_range(timestamp, window)
        return {
            'query_name': 'Authentication Events',
            'kql': f'user.name: "{username}" AND (event.category: "authentication" OR event.action: "logon")',
            'time_range': {'gte': start, 'lte': end},
            'index_pattern': 'logs-windows-*,logs-endpoint-*',
            'size': 100,
        }
