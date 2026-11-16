"""Run the prequeries for one alert from the command line.

Examples (from the repository root):
  python kibana_queries/run_prequery.py --alert alert.json --dry-run
  python kibana_queries/run_prequery.py --alert alert.json

A live run reads ES_URL and ES_API_KEY from the environment,
plus ES_CA_CERT if the instance uses its own CA.
"""
import argparse
import json
import os
import sys

from results_formatter import ResultsFormatter


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='Run Kibana prequeries for '
                                             'one alert.')
    ap.add_argument('--alert', required=True, help='alert JSON file')
    ap.add_argument('--rule', help='rule key, for example netcat '
                                   '(detected from the alert if omitted)')
    ap.add_argument('--window', type=int, default=15,
                    help='minutes before the alert to search (default 15)')
    ap.add_argument('--dry-run', action='store_true',
                    help='show the queries without searching')
    args = ap.parse_args(argv)

    if not args.dry_run and not (os.environ.get('ES_URL')
                                 or os.environ.get('KIBANA_URL')):
        ap.error('set ES_URL (and ES_API_KEY), or use --dry-run')

    with open(args.alert, encoding='utf-8') as f:
        alert = json.load(f)
    result = ResultsFormatter.from_env().process_alert(
        alert, time_window_minutes=args.window, rule_name=args.rule,
        dry_run=args.dry_run)
    result.pop('original_alert', None)
    json.dump(result, sys.stdout, indent=2, default=str)
    print()
    return 0


if __name__ == '__main__':
    sys.exit(main())
