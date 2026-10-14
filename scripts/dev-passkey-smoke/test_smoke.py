import argparse
import hashlib
import contextlib
import io
import urllib.error
import json
import signal
import threading
import tempfile
from pathlib import Path
import time
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, MagicMock, patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import smoke


def args(**overrides):
    value = dict(base_url=smoke.DEV, approve_synthetic_dev=True, local_test=False, include_expiry=False)
    value.update(overrides)
    return argparse.Namespace(**value)


class SafetyTests(unittest.TestCase):
    def test_target_and_approval_fail_before_network(self):
        for settings in [args(base_url='https://api.rsrs.rs'), args(approve_synthetic_dev=False),
                         args(local_test=True, base_url=smoke.DEV),
                         args(local_test=True, base_url='http://localhost:1234'),
                         args(local_test=True, base_url='http://127.0.0.1:1234/private'),
                         args(local_test=True, base_url='http://x@127.0.0.1:1234')]:
            runner = smoke.Smoke(settings)
            runner.request = Mock()
            with self.assertRaises(smoke.Failure):
                runner.preflight()
            runner.request.assert_not_called()
            self.assertEqual(runner.accounts, [])

    def test_wrong_sha_and_unready_never_create_accounts_even_locally(self):
        for local in (False, True):
            for replies in [[{'ok': True, 'service': 'respire', 'source_revision': 'a' * 40}],
                            [{'ok': True, 'service': 'respire', 'source_revision': smoke.SHA}, {'ok': False}]]:
                runner = smoke.Smoke(args(local_test=local, base_url='http://127.0.0.1:1234' if local else smoke.DEV))
                runner.request = Mock(side_effect=replies)
                with self.assertRaises(smoke.Failure):
                    runner.preflight()
                self.assertEqual(runner.accounts, [])
                self.assertTrue(all(c.args[0] == 'GET' for c in runner.request.call_args_list))

    def test_signed_wrong_values_still_have_valid_ecdsa_signatures(self):
        auth = smoke.Authenticator()
        auth.account = str(uuid.uuid4())
        envelope = {'mode': 'trusted_browser', 'public_key': {'challenge': smoke.b64(b'c' * 32)}}
        for changes in [{}, {'uv': False}, {'origin': 'https://wrong.example.com'},
                        {'rp': 'other.example.com'}, {'challenge': smoke.b64(b'x' * 32)}]:
            credential = auth.assertion(envelope, **changes)
            response = credential['response']
            data, client = smoke.un64(response['authenticatorData']), smoke.un64(response['clientDataJSON'])
            auth.key.public_key().verify(smoke.un64(response['signature']), data + hashlib.sha256(client).digest(),
                                         ec.ECDSA(hashes.SHA256()))
            self.assertEqual(bool(data[32] & 4), changes.get('uv', True))
            self.assertEqual(data[:32], hashlib.sha256(changes.get('rp', smoke.RP).encode()).digest())
            self.assertEqual(json.loads(client)['origin'], changes.get('origin', smoke.ORIGIN))
            self.assertNotIn('results', json.dumps(credential['clientExtensionResults']))

    def test_unverified_identity_cleanup_never_mutates(self):
        runner = smoke.Smoke(args())
        runner.accounts = [{'user': 'synthetic', 'confirmed': True, 'identity_verified': False}]
        runner.request = Mock()
        runner.cleanup()
        runner.request.assert_not_called()
        self.assertEqual(runner.cleanup_events[0]['state'], 'identity-unverified-cleanup-skipped')

    def test_report_does_not_include_runtime_secrets(self):
        runner = smoke.Smoke(args())
        runner.accounts = [{'token': 'secret-token-canary', 'private_key': 'secret-key-canary'}]
        report = json.dumps(runner.report('constant-error'))
        self.assertNotIn('secret-', report)
        self.assertNotIn('private_key', report)
        self.assertEqual(smoke.cbor({1: 2, -1: 1}).hex(), 'a201022001')

    def test_expiry_requested_is_not_expiry_tested(self):
        runner = smoke.Smoke(args(include_expiry=True))
        self.assertTrue(runner.report('preflight-failure')['expiry_requested'])
        self.assertFalse(runner.report('preflight-failure')['expiry_tested'])
        runner.events.append('five-minute-expiry')
        self.assertTrue(runner.report(None)['expiry_tested'])

    def test_slow_trickle_body_is_interrupted_by_total_request_deadline(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                body = b'{"x":"' + b'x' * 100 + b'"}'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    for byte in body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(.02)
                except OSError:
                    pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            runner = smoke.Smoke(args(local_test=True, base_url='http://127.0.0.1:' + str(server.server_port)))
            started = time.monotonic()
            with smoke.Deadlines(started + 2, per_request=.15) as deadlines:
                runner.deadlines = deadlines
                with self.assertRaises(smoke.RequestDeadline):
                    runner.request('GET', '/trickle')
            self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(runner.requests, 1)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

    def test_http_redirect_is_not_followed(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                seen.append(self.path)
                self.send_response(302)
                self.send_header('Location', '/must-not-follow')
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'{}')

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            runner = smoke.Smoke(args(local_test=True, base_url='http://127.0.0.1:' + str(server.server_port)))
            with smoke.Deadlines(time.monotonic() + 2) as deadlines:
                runner.deadlines = deadlines
                with self.assertRaisesRegex(smoke.Failure, 'unexpected-http-status-302'):
                    runner.request('GET', '/redirect')
            self.assertEqual(seen, ['/redirect'])
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

    def test_response_read_is_size_bounded(self):
        runner = smoke.Smoke(args())
        response = MagicMock()
        response.__enter__.return_value = response
        response.code = 200
        response.read.return_value = b'x' * (smoke.MAX_RESPONSE + 1)
        runner.http.open = Mock(return_value=response)
        with smoke.Deadlines(time.monotonic() + 2) as deadlines:
            runner.deadlines = deadlines
            with self.assertRaisesRegex(smoke.Failure, 'response-too-large'):
                runner.request('GET', '/oversized')
        response.read.assert_called_once_with(smoke.MAX_RESPONSE + 1)

    def test_request_timeout_restores_original_total_deadline_and_handler(self):
        previous = signal.getsignal(signal.SIGALRM)
        start = time.monotonic()
        with self.assertRaises(smoke.TotalDeadline):
            with smoke.Deadlines(start + .20, per_request=.05) as deadlines:
                with self.assertRaises(smoke.RequestDeadline):
                    with deadlines.request():
                        time.sleep(2)
                time.sleep(2)
        self.assertLess(time.monotonic() - start, .8)
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_total_deadline_interrupts_wait_and_does_not_start_cleanup(self):
        runner = smoke.Smoke(args())
        runner.run = Mock(side_effect=lambda: time.sleep(2))
        runner.cleanup = Mock()
        self.assertEqual(smoke.execute(runner, total_seconds=.05), 'overall-deadline-cleanup-may-be-incomplete')
        runner.cleanup.assert_not_called()
        self.assertLess(time.monotonic() - runner.started, .8)

    def test_total_deadline_escapes_cleanup_and_marks_unfinished_accounts(self):
        runner = smoke.Smoke(args())
        runner.run = Mock()
        runner.accounts = [{'user': name, 'confirmed': True, 'identity_verified': True} for name in ('synthetic-a', 'synthetic-b')]
        runner.request = Mock(side_effect=smoke.TotalDeadline())
        self.assertEqual(smoke.execute(runner), 'overall-deadline-cleanup-may-be-incomplete')
        self.assertEqual(runner.request.call_count, 1)
        self.assertEqual(len(runner.cleanup_events), 2)
        self.assertTrue(all(e['state'].endswith('manual-review-required') for e in runner.cleanup_events))

    def test_revised_fixed_limits_and_safe_route_templates(self):
        self.assertEqual((smoke.REQUEST_SECONDS, smoke.TOTAL_SECONDS, smoke.MAX_REQUESTS, smoke.MAX_RESPONSE),
                         (30, 1800, 180, 1048576))
        self.assertEqual(smoke.Smoke.diagnostic_route('/api/self/vault?token=secret-query-canary'), '/api/self/vault')
        self.assertEqual(smoke.Smoke.diagnostic_route('/api/self/sessions/secret-id-canary/revoke?secret'),
                         '/api/self/sessions/:session_id/revoke')
        self.assertEqual(smoke.Smoke.diagnostic_route('/secret-path-canary'), '<other-route>')

    def test_diagnostics_redact_body_token_query_identifier_and_exception(self):
        runner = smoke.Smoke(args())
        runner.cleaning = True
        runner.http.open = Mock(side_effect=urllib.error.URLError('secret-exception-canary'))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with smoke.Deadlines(time.monotonic() + 2) as deadlines:
                runner.deadlines = deadlines
                with self.assertRaisesRegex(smoke.Failure, 'network-error-no-retry'):
                    runner.request('POST', '/api/self/sessions/secret-id-canary/revoke?token=secret-query-canary',
                                   {'secret-body-canary': 'secret-value-canary'}, token='secret-token-canary')
        report = runner.report('constant-error')
        self.assertNotIn('secret-', json.dumps(report) + output.getvalue())
        self.assertEqual(report['request_diagnostics'][0]['route'], '/api/self/sessions/:session_id/revoke')
        self.assertEqual(report['request_diagnostics'][0]['stage'], 'cleanup')
        self.assertEqual(report['request_diagnostics'][0]['outcome'], 'failed')
        self.assertIsInstance(report['request_diagnostics'][0]['elapsed_seconds'], float)
        self.assertEqual(runner.http.open.call_count, 1)
        self.assertEqual(runner.http.open.call_args.kwargs['timeout'], 30)

    def test_public_journal_precedes_registration_and_never_persists_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'progress.json'
            runner = smoke.Smoke(args(journal=path))
            output = io.StringIO()
            def reply(method, route, body=None, owner=None):
                journal = json.loads(path.read_text())
                if route == '/register':
                    self.assertEqual(journal['accounts'][0]['user'], body['user'])
                    self.assertFalse(journal['accounts'][0]['creation_confirmed'])
                    self.assertIn('ACCOUNT creation-pending', output.getvalue())
                    return {'user': body['user'], 'token': 'secret-token-canary', 'session_id': 'secret-session-canary'}
                self.assertTrue(journal['accounts'][0]['creation_confirmed'])
                if route == '/api/self':
                    return {'user': owner['user']}
                self.assertTrue(journal['accounts'][0]['identity_verified'])
                return {'enabled': True, 'trusted_browser_enabled': True, 'rp_id': smoke.RP, 'origin': smoke.ORIGIN}
            runner.request = Mock(side_effect=reply)
            with contextlib.redirect_stdout(output):
                owner = runner.register_account('a')
            owner['account_id'] = str(uuid.uuid4())
            runner.checkpoint()
            journal = path.read_text()
            self.assertNotIn('secret-', journal + output.getvalue())
            self.assertNotIn('token', journal)
            self.assertNotIn('sessions', journal)
            self.assertEqual(json.loads(journal)['accounts'][0]['account_id'], owner['account_id'])
            self.assertEqual(len(list(Path(temp).iterdir())), 1)

    def test_uncertain_registration_leaves_public_pending_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'progress.json'
            runner = smoke.Smoke(args(journal=path))
            runner.request = Mock(side_effect=smoke.Failure('network-error-no-retry'))
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(smoke.Failure):
                runner.register_account('a')
            public = json.loads(path.read_text())['accounts'][0]
            self.assertEqual(public['user'], runner.accounts[0]['user'])
            self.assertFalse(public['creation_confirmed'])
            self.assertIsNotNone(public['registration_requested_at_client_utc'])
            self.assertEqual(runner.request.call_count, 1)

    def test_atomic_json_failure_preserves_previous_public_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'progress.json'
            smoke.atomic_json(path, {'previous': True})
            with patch.object(smoke.os, 'replace', side_effect=OSError('redacted')):
                with self.assertRaises(OSError):
                    smoke.atomic_json(path, {'new': True})
            self.assertEqual(json.loads(path.read_text()), {'previous': True})
            self.assertEqual(len(list(Path(temp).iterdir())), 1)

    def test_journal_failure_stops_acceptance_but_allows_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            runner = smoke.Smoke(args(journal=Path(temp) / 'missing' / 'progress.json'))
            with contextlib.redirect_stdout(io.StringIO()):
                runner.checkpoint()
                runner._request = Mock(return_value={})
                with self.assertRaisesRegex(smoke.Failure, 'public-journal-unavailable'):
                    runner.request('POST', '/register')
                runner._request.assert_not_called()
                runner.cleaning = True
                runner.request('GET', smoke.P)
            self.assertEqual(runner._request.call_count, 1)

    def test_final_journal_failure_cannot_report_success(self):
        runner = smoke.Smoke(args())
        runner.run = Mock()
        runner.cleanup = Mock()
        def fail_final(**_):
            runner.journal_failed = True
        runner.checkpoint = Mock(side_effect=fail_final)
        self.assertEqual(smoke.execute(runner), 'public-journal-write-failed')
        runner.checkpoint.assert_called_once_with(state='finished', failure=None)

    def test_malformed_public_account_uuid_is_not_logged(self):
        for value in ({'secret-key-canary': 'secret-value-canary'}, 123, 'secret-token-canary', 'x' * 100):
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / 'progress.json'
                runner = smoke.Smoke(args(journal=path))
                runner.accounts = [{'user': 'synthetic', 'confirmed': True, 'identity_verified': True, 'account_id': value}]
                with self.assertRaisesRegex(smoke.Failure, 'invalid-public-account-uuid'):
                    runner.checkpoint()
                self.assertFalse(path.exists())
        value = str(uuid.uuid4())
        self.assertEqual(smoke.canonical_uuid(value), value)

    def test_existing_process_alarm_is_refused_without_replacing_it(self):
        signal.setitimer(signal.ITIMER_REAL, 30)
        try:
            with self.assertRaises(smoke.Failure):
                with smoke.Deadlines(time.monotonic() + 1):
                    self.fail('existing alarm must be refused')
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 20)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    unittest.main()
