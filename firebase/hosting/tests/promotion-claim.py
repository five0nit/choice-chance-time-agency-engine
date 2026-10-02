"""Isolated emulator trigger proof with archived genuine discovery, NO research effects."""
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

if os.environ.get('FIRESTORE_EMULATOR_HOST') != '127.0.0.1:8080':
    raise RuntimeError('EMULATOR_REQUIRED')
repo = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo))
from cct_agent import owner_work as work
from google.auth.credentials import AnonymousCredentials
from google.cloud import firestore
discovery_db = Path(os.environ['CCT_QA_DISCOVERY_DB']).resolve()
data = json.loads((Path(os.environ['CCT_QA_OUTPUT']) / 'owner-work-live.json').read_text())
identity = {'ownerUid': data['workspace']['ownerUid'], 'projectId': 'demo-cctae-browser'}
dialogue = {'conversationId': data['discovery']['conversationId'], 'enabled': True}
gateway = work.FirebaseOwnerGateway.__new__(work.FirebaseOwnerGateway)
gateway.db = firestore.Client(project=identity['projectId'], credentials=AnonymousCredentials())
with tempfile.TemporaryDirectory(prefix='cct-promotion-claim-') as temp:
    home = Path(temp)
    (home / 'owner-connection').mkdir()
    with sqlite3.connect(discovery_db.as_uri() + '?mode=ro', uri=True) as source:
        with sqlite3.connect(home / 'owner-connection/discovery.sqlite') as destination:
            source.backup(destination)
            destination.execute("UPDATE meta SET value=? WHERE key='identity'", (work.dumps(identity),))
    with patch.object(work, 'load_config', return_value=identity), patch.object(work, 'dialogue_config', return_value=dialogue), patch.object(work, 'FirebaseOwnerGateway', return_value=gateway):
        worker = work.OwnerWork(home)
        try:
            config = {'authorization': 'operator://isolated-emulator-proof-no-research'}
            worker.ingest_promotions(config)
            worker.ingest_promotions(config)
            rows = worker.db.execute('SELECT payload FROM jobs').fetchall()
            assert len(rows) == 1
            job = json.loads(rows[0][0])
            assert job['phase'] == 'QUEUED' and job['webAttempts'] == job['modelCalls'] == 0
            assert job['promotedIdea'] == data['discovery']['workIdeas'][0]
            worker.publish(job)
            restarted = work.OwnerWork(home)
            try:
                assert restarted.db.execute('SELECT phase FROM jobs').fetchone()[0] == 'QUEUED'
            finally:
                restarted.close()
            receipt = {'mode': 'EMULATOR_ONLY', 'requestId': job['requestId'], 'jobId': job['id'],
                       'phase': job['phase'], 'exactArchivedIdea': True, 'deduplicated': True,
                       'restartQueuePreserved': True, 'modelCalls': 0, 'publicFetches': 0}
            print(json.dumps(receipt))
        finally:
            worker.close()
