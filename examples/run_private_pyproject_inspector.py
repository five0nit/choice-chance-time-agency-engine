"""Run the fixed, offline pyproject inspector example through mandatory isolation.

Requires an installed cct-agency-engine and supported Linux sandbox interpreter.
Neither the bundle nor its tests are imported/executed by this host launcher.
"""
import argparse
import json
from pathlib import Path

from cct_agent.owner_delivery_local import LocalDeliveryDriver


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path,
                        help='Absolute private artifact directory; not a live delivery root.')
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    bundle = json.loads((base / 'pyproject-inspector.bundle.json').read_text(encoding='utf-8'))
    acceptance = json.loads((base / 'pyproject-inspector.acceptance.json').read_text(encoding='utf-8'))
    receipt = LocalDeliveryDriver(args.root).run('pyproject-inspector-example', bundle, acceptance=acceptance)
    print(json.dumps(receipt, sort_keys=True, indent=2))
    return 0 if receipt['status'] == 'completed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
