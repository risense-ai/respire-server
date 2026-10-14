#!/usr/bin/env python3
"""Reconstructed Linux-only synthetic API acceptance; not provider/browser certification."""
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import signal
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SHA = '686f1d1e84721675906e792c71b96cde4772429e'
DEV = 'https://api.dev.rsrs.rs'
ORIGIN = 'https://dash.dev.rsrs.rs'
RP = 'dash.dev.rsrs.rs'
P = '/api/self/passkeys'
KDFS = {'prf': 'webauthn-prf-hkdf-sha256-v1', 'trusted_browser': 'trusted-browser-aes256gcm-v1'}
MAX_REQUESTS = 180
MAX_RESPONSE = 1024 * 1024
REQUEST_SECONDS = 30
TOTAL_SECONDS = 1800


class Failure(Exception):
    """Messages are constant reason codes, never server content or secret material."""


def check(condition, code):
    if not condition:
        raise Failure(code)


class TotalDeadline(Failure):
    def __init__(self):
        super().__init__('overall-deadline-cleanup-may-be-incomplete')


class RequestDeadline(Failure):
    def __init__(self):
        super().__init__('http-total-deadline-no-retry')


class Deadlines:
    """One Linux main-thread SIGALRM owner, two absolute monotonic deadlines."""
    def __init__(self, deadline, per_request=REQUEST_SECONDS):
        self.deadline = deadline
        self.per_request = per_request
        self.request_at = None
        self.active = False
        self.expired = False
        self.old_handler = None

    def __enter__(self):
        check(sys.platform.startswith('linux') and threading.current_thread() is threading.main_thread(),
              'standalone-linux-main-thread-required')
        check(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'existing-active-alarm-refused')
        if time.monotonic() >= self.deadline:
            raise TotalDeadline()
        self.old_handler = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, self._alarm)
        self.active = True
        try:
            signal.setitimer(signal.ITIMER_REAL, max(0.000001, self.deadline - time.monotonic()))
            return self
        except BaseException:
            self.__exit__()
            raise

    def __exit__(self, *_):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.old_handler)
        self.active = False

    def _alarm(self, *_):
        if self.request_at is None or time.monotonic() >= self.deadline:
            self.expired = True
            raise TotalDeadline()
        raise RequestDeadline()

    @contextmanager
    def request(self):
        check(self.active and threading.current_thread() is threading.main_thread(), 'active-deadline-required')
        check(self.request_at is None, 'nested-request-refused')
        now = time.monotonic()
        if self.expired or now >= self.deadline:
            self.expired = True
            raise TotalDeadline()
        self.request_at = min(now + self.per_request, self.deadline)
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, self.request_at - now))
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            self.request_at = None
            remaining = self.deadline - time.monotonic()
            if remaining > 0:
                signal.setitimer(signal.ITIMER_REAL, remaining)


def atomic_json(path, value):
    # Public allowlisted metadata only; never a credential-storage mechanism.
    path = Path(path)
    temp = path.with_name(path.name + '.tmp-' + secrets.token_hex(8))
    try:
        with temp.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(value, indent=2) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def canonical_uuid(value):
    check(isinstance(value, str), 'invalid-public-account-uuid')
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise Failure('invalid-public-account-uuid') from None
    check(str(parsed) == value, 'invalid-public-account-uuid')
    return value


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def un64(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def cbor(value):
    """Fixed synthetic none-attestation encoder; not a general parser or verifier."""
    def head(major, size):
        if size < 24:
            return bytes([(major << 5) | size])
        if size < 256:
            return bytes([(major << 5) | 24, size])
        if size < 65536:
            return bytes([(major << 5) | 25]) + struct.pack('>H', size)
        raise Failure('fixture-cbor-too-large')
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1-value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode()
        return head(3, len(encoded)) + encoded
    if isinstance(value, dict):
        return head(5, len(value)) + b''.join(cbor(k) + cbor(v) for k, v in value.items())
    raise Failure('unsupported-fixture-cbor')


class Authenticator:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.id = b64(secrets.token_bytes(32))
        self.account = None
        self.counter = 0
        self.prf_seed = secrets.token_bytes(32)

    def client(self, envelope, kind, origin=ORIGIN, challenge=None):
        return compact({'type': kind, 'origin': origin, 'crossOrigin': False,
                        'challenge': challenge or envelope['public_key']['challenge']})

    def credential(self, envelope, response):
        return {'id': self.id, 'rawId': self.id, 'type': 'public-key', 'response': response,
                'clientExtensionResults': {'prf': {'enabled': True}} if envelope['mode'] == 'prf' else {}}

    def register(self, envelope, uv=True):
        self.account = envelope['account_id']
        check(envelope['public_key']['rp']['id'] == RP, 'creation-rp-mismatch')
        check(un64(envelope['public_key']['user']['id']) == uuid.UUID(self.account).bytes, 'creation-user-handle-mismatch')
        point = self.key.public_key().public_numbers()
        cose = {1: 2, 3: -7, -1: 1, -2: point.x.to_bytes(32, 'big'), -3: point.y.to_bytes(32, 'big')}
        raw_id = un64(self.id)
        data = (hashlib.sha256(RP.encode()).digest() + bytes([0x41 | (4 if uv else 0)])
                + struct.pack('>I', self.counter) + bytes(16) + struct.pack('>H', len(raw_id)) + raw_id + cbor(cose))
        return self.credential(envelope, {'clientDataJSON': b64(self.client(envelope, 'webauthn.create')),
            'attestationObject': b64(cbor({'fmt': 'none', 'attStmt': {}, 'authData': data})), 'transports': ['internal']})

    def assertion(self, envelope, uv=True, origin=ORIGIN, rp=RP, challenge=None, account=None):
        self.counter += 1
        client = self.client(envelope, 'webauthn.get', origin, challenge)
        data = hashlib.sha256(rp.encode()).digest() + bytes([1 | (4 if uv else 0)]) + struct.pack('>I', self.counter)
        signature = self.key.sign(data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return self.credential(envelope, {'clientDataJSON': b64(client), 'authenticatorData': b64(data),
            'signature': b64(signature), 'userHandle': b64(uuid.UUID(account or self.account).bytes)})


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


class Smoke:
    def __init__(self, args):
        self.args = args
        self.journal = getattr(args, "journal", None)
        self.journal_failed = False
        self.started_at = dt.datetime.now(dt.timezone.utc).isoformat()
        self.base = args.base_url.rstrip('/')
        self.started = time.monotonic()
        self.deadlines = None
        self.http = urllib.request.build_opener(NoRedirect())
        self.requests = 0
        self.accounts = []
        self.pending = []
        self.events = []
        self.cleanup_events = []
        self.request_diagnostics = []
        self.cleaning = False
        self.limits = {"request_seconds": REQUEST_SECONDS, "overall_seconds": TOTAL_SECONDS,
                       "max_requests": MAX_REQUESTS, "max_response_bytes": MAX_RESPONSE}
        self.namespace = 'tb-smoke-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d%H%M%S') + '-' + secrets.token_hex(4)

    def checkpoint(self, state='running', failure=None):
        if self.journal is None:
            return
        public = {'state': state, 'run_id': self.namespace, 'source_revision_required': SHA,
            'started_at_client_utc': self.started_at, 'updated_at_client_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'requests': self.requests, 'stage': 'cleanup' if self.cleaning else 'acceptance',
            'last_request': self.request_diagnostics[-1] if self.request_diagnostics else None,
            'checks_passed': self.events, 'failure_code': failure, 'cleanup': self.cleanup_events,
            'accounts': [{'user': a['user'], 'creation_confirmed': a['confirmed'],
                          'identity_verified': a['identity_verified'],
                          'account_id': None if a.get('account_id') is None else canonical_uuid(a['account_id']),
                          'registration_requested_at_client_utc': a.get('registration_requested_at_client_utc'),
                          'registration_confirmed_at_client_utc': a.get('registration_confirmed_at_client_utc')}
                         for a in self.accounts]}
        try:
            atomic_json(self.journal, public)
        except OSError:
            self.journal_failed = True  # Do not start another request except scoped cleanup.
            print('WARN public-journal-write-failed', flush=True)

    def event(self, name):
        self.events.append(name)
        print('PASS ' + name, flush=True)
        self.checkpoint()

    @staticmethod
    def diagnostic_route(path):
        # Only hardcoded route names, never query strings or caller/server identifiers.
        clean = path.partition('?')[0]
        if clean.startswith('/api/self/sessions/') and clean.endswith('/revoke'):
            return '/api/self/sessions/:session_id/revoke'
        allowed = {'/health', '/ready', '/register', '/api/self', '/api/self/vault',
                   '/api/self/vault/reset', '/push', '/pull', '/api/self/sessions', P}
        allowed.update(P + suffix for suffix in ('/register/start', '/register/finish',
            '/register/test', '/register/commit', '/unlock/start', '/unlock/finish', '/remove', '/cancel'))
        return clean if clean in allowed else '<other-route>'

    def request(self, method, path, body=None, owner=None, token=None, expected=200):
        check(not self.journal_failed or self.cleaning, 'public-journal-unavailable-before-next-request')
        started = time.monotonic()
        diagnostic = {'number': self.requests + 1, 'method': method if method in ('GET', 'POST') else '<other-method>',
                      'route': self.diagnostic_route(path), 'stage': 'cleanup' if self.cleaning else 'acceptance',
                      'outcome': 'interrupted'}
        try:
            value = self._request(method, path, body, owner, token, expected, diagnostic)
            diagnostic['outcome'] = 'ok'
            return value
        except RequestDeadline:
            diagnostic['outcome'] = 'request-deadline'
            raise
        except TotalDeadline:
            diagnostic['outcome'] = 'overall-deadline'
            raise
        except Exception:
            diagnostic['outcome'] = 'failed'
            raise
        finally:
            diagnostic['elapsed_seconds'] = round(time.monotonic() - started, 3)
            self.request_diagnostics.append(diagnostic)
            self.checkpoint()
            if diagnostic['outcome'] != 'ok':
                print('REQUEST ' + json.dumps(diagnostic, separators=(',', ':')), flush=True)

    def _request(self, method, path, body, owner, token, expected, diagnostic):
        check(self.deadlines is not None, 'active-deadline-required')
        with self.deadlines.request():
            self.requests += 1
            check(self.requests <= MAX_REQUESTS, 'request-budget-exhausted')
            check(path.startswith('/') and not path.startswith('//'), 'relative-path-required')
            headers = {'Accept': 'application/json', 'Cache-Control': 'no-store'}
            if owner:
                check(owner in self.accounts and owner['confirmed'], 'fresh-fixture-account-required')
                if method != 'GET':
                    check(owner['identity_verified'], 'fixture-token-identity-unverified')
                token = token or owner['token']
            if token:
                headers['Authorization'] = 'Bearer ' + token
            data = None if body is None else compact(body)
            if data is not None:
                headers['Content-Type'] = 'application/json'
            req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
            try:
                response = self.http.open(req, timeout=self.deadlines.per_request)
            except urllib.error.HTTPError as error:
                response = error
            except (OSError, urllib.error.URLError):
                raise Failure('network-error-no-retry') from None
            with response:
                status = response.code
                diagnostic['http_status'] = status
                raw = response.read(MAX_RESPONSE + 1)
                cache = response.headers.get('Cache-Control', '')
            check(status == expected, 'unexpected-http-status-' + str(status) + '-expected-' + str(expected))
            check(len(raw) <= MAX_RESPONSE, 'response-too-large')
            if path.startswith(P):
                check('no-store' in cache.lower(), 'passkey-response-missing-no-store')
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeError):
                raise Failure('invalid-response-json') from None
            check(isinstance(value, dict), 'response-object-required')
            return value

    def preflight(self):
        if self.args.local_test:
            url = urllib.parse.urlsplit(self.base)
            check(url.scheme == 'http' and url.hostname == '127.0.0.1' and url.port is not None
                  and not url.username and not url.password and not url.path and not url.query and not url.fragment,
                  'local-mode-explicit-loopback-port-required')
        else:
            check(self.args.approve_synthetic_dev and self.base == DEV, 'exact-dev-url-and-approval-required')
        health = self.request('GET', '/health')
        check(health.get('ok') is True and health.get('service') == 'respire' and health.get('source_revision') == SHA,
              'pinned-source-revision-mismatch')
        ready = self.request('GET', '/ready')
        check(ready.get('ok') is True and ready.get('database') == 'ready', 'schema9-readiness-required')
        self.event('exact-source-sha-and-schema9-readiness')

    def register_account(self, suffix):
        owner = {'user': self.namespace + '-' + suffix, 'confirmed': False, 'identity_verified': False,
                 'token': None, 'sessions': [], 'account_id': None,
                 'registration_requested_at_client_utc': dt.datetime.now(dt.timezone.utc).isoformat()}
        self.accounts.append(owner)  # Creation may succeed even if its response is lost; never retry it.
        self.checkpoint()  # Persist the public username BEFORE a possibly committed registration.
        print('ACCOUNT creation-pending ' + json.dumps({'user': owner['user'],
            'registration_requested_at_client_utc': owner['registration_requested_at_client_utc']}), flush=True)
        result = self.request('POST', '/register', {'user': owner['user'], 'pass_hash': secrets.token_hex(32),
            'salt': secrets.token_hex(16), 'device_name': 'synthetic-trusted-browser-smoke'})
        check(result.get('user') == owner['user'] and isinstance(result.get('token'), str)
              and isinstance(result.get('session_id'), str), 'fixture-registration-contract')
        owner.update(confirmed=True, token=result['token'])
        owner['sessions'].append(result['session_id'])
        owner['registration_confirmed_at_client_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
        self.checkpoint()
        check(self.request('GET', '/api/self', owner=owner).get('user') == owner['user'], 'fixture-account-identity')
        owner['identity_verified'] = True
        self.checkpoint()
        listing = self.request('GET', P, owner=owner)
        check(listing.get('enabled') is True and listing.get('trusted_browser_enabled') is True, 'dev-feature-flags-required')
        check(listing.get('rp_id') == RP and listing.get('origin') == ORIGIN, 'exact-dev-rp-origin-required')
        return owner

    def vault(self, owner, urk, generation=None, reset=False):
        recovery_key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
        body = {'version': 4, 'kdf_salt': secrets.token_hex(16), 'urk_nonce': b64(nonce),
                'wrapped_urk': b64(AESGCM(recovery_key).encrypt(nonce, urk, b'synthetic-recovery-fixture'))}
        if generation is not None:
            body['expected_key_generation'] = generation
            if not reset:
                body['operation'] = 'rewrap_same_urk'
        self.request('POST', '/api/self/vault/reset' if reset else '/api/self/vault', body, owner)
        saved = self.request('GET', '/api/self/vault', owner=owner)
        owner['account_id'] = canonical_uuid(saved['account_id'])
        self.checkpoint()
        for field in ('version', 'kdf_salt', 'urk_nonce', 'wrapped_urk'):
            check(saved[field] == body[field], 'recovery-wrapper-not-preserved')
        check(AESGCM(recovery_key).decrypt(un64(saved['urk_nonce']), un64(saved['wrapped_urk']),
              b'synthetic-recovery-fixture') == urk, 'recovery-fixture-roundtrip')
        return saved

    def remember(self, owner, envelope):
        self.pending.append((owner, envelope['ceremony_id']))
        check(envelope['account_id'] == owner['account_id'] and envelope['rp_id'] == RP, 'ceremony-account-rp-mismatch')
        return envelope

    def body(self, envelope, credential):
        result = {'ceremony_id': envelope['ceremony_id'], 'credential': credential}
        if envelope['mode'] == 'trusted_browser':
            result.update(mode='trusted_browser', device_id=envelope['device_id'])
        return result

    def selector(self, envelope):
        result = {'credential_id': envelope['credential_id']}
        if envelope['mode'] == 'trusted_browser':
            result.update(mode='trusted_browser', device_id=envelope['device_id'])
        return result

    def start(self, owner, mode='trusted_browser'):
        body = {'label': 'Synthetic DEV ' + mode}
        if mode == 'trusted_browser':
            body.update(mode=mode, device_id=str(uuid.uuid4()))
        envelope = self.remember(owner, self.request('POST', P + '/register/start', body, owner))
        check(envelope['mode'] == mode and envelope.get('trusted_browser_enabled') is True, 'creation-mode-mismatch')
        if mode == 'trusted_browser':
            check(envelope['device_id'] == body['device_id'] and 'prf' not in envelope['public_key'].get('extensions', {}),
                  'trusted-create-must-not-require-prf')
        check(envelope['public_key']['authenticatorSelection']['userVerification'] == 'required', 'creation-uv-required')
        return envelope

    def advance(self, owner, route, old, credential):
        envelope = self.remember(owner, self.request('POST', P + route, self.body(old, credential), owner))
        for field in ('mode', 'account_id', 'rp_id', 'key_generation', 'device_id'):
            check(envelope.get(field) == old.get(field), 'changed-ceremony-binding')
        check(envelope['public_key']['challenge'] != old['public_key']['challenge'], 'fresh-challenge-required')
        check(envelope['public_key']['userVerification'] == 'required', 'assertion-uv-required')
        return envelope

    def aad(self, envelope):
        fields = [envelope[k] for k in ('account_id', 'rp_id', 'credential_id', 'key_generation')]
        if envelope['mode'] == 'trusted_browser':
            return compact(['respire:trusted-browser:urk-wrap:v1', *fields, envelope['device_id']])
        return compact(['respire:passkey:urk-wrap:v1', *fields, envelope['prf_salt']])

    def wrapping_key(self, auth, envelope, device_key):
        if envelope['mode'] == 'trusted_browser':
            return device_key
        # This is deliberately simulated PRF, not provider compatibility evidence.
        prf = hmac.digest(auth.prf_seed, un64(envelope['prf_salt']), 'sha256')
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=un64(envelope['prf_salt']),
                    info=b'respire:passkey:urk-wrap:v1').derive(prf)

    def fixture_wrapper(self):
        # A syntactically valid opaque wrapper for negative requests expected never to activate.
        return {'version': 1, 'kdf': KDFS['trusted_browser'], 'nonce': b64(secrets.token_bytes(12)),
                'wrapped_urk': b64(secrets.token_bytes(48))}

    def enroll(self, owner, urk, mode='trusted_browser'):
        auth = Authenticator()
        start = self.start(owner, mode)
        first = self.advance(owner, '/register/finish', start, auth.register(start))
        device_key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
        wrapper = {'version': 1, 'kdf': KDFS[mode], 'nonce': b64(nonce),
            'wrapped_urk': b64(AESGCM(self.wrapping_key(auth, first, device_key)).encrypt(nonce, urk, self.aad(first)))}
        signed = auth.assertion(first)
        self.request('POST', P + '/register/commit', dict(self.body(first, signed), wrapper=wrapper), owner, expected=400)
        second = self.advance(owner, '/register/test', first, signed)
        check(AESGCM(self.wrapping_key(auth, second, device_key)).decrypt(nonce, un64(wrapper['wrapped_urk']),
              self.aad(second)) == urk, 'independent-wrapper-roundtrip')
        body = dict(self.body(second, auth.assertion(second)), wrapper=wrapper)
        self.request('POST', P + '/register/commit', body, owner)
        self.request('POST', P + '/register/commit', body, owner, expected=400)
        entries = self.request('GET', P, owner=owner)['credentials']
        check(any(e['credential_id'] == auth.id and e['mode'] == mode for e in entries), 'credential-not-active')
        check(not any('wrapper' in e or 'wrapped_urk' in e for e in entries), 'list-exposed-wrapper')
        self.event(mode + '-two-fresh-uv-enrollment-commit-replay')
        return second, auth, device_key

    def unlock_start(self, owner, enrollment):
        envelope = self.remember(owner, self.request('POST', P + '/unlock/start', self.selector(enrollment), owner))
        for field in ('mode', 'device_id', 'account_id', 'rp_id', 'credential_id', 'key_generation'):
            check(envelope.get(field) == enrollment.get(field), 'unlock-context-mismatch')
        return envelope

    def unlock(self, owner, enrolled, urk):
        enrollment, auth, key = enrolled
        envelope = self.unlock_start(owner, enrollment)
        body = self.body(envelope, auth.assertion(envelope))
        released = self.request('POST', P + '/unlock/finish', body, owner)
        for field in ('mode', 'device_id', 'account_id', 'rp_id', 'credential_id', 'key_generation'):
            check(released.get(field) == enrollment.get(field), 'released-context-mismatch')
        wrapper = released['wrapper']
        check(wrapper['kdf'] == KDFS[enrollment['mode']], 'released-wrapper-mode')
        check(AESGCM(self.wrapping_key(auth, released, key)).decrypt(un64(wrapper['nonce']), un64(wrapper['wrapped_urk']),
              self.aad(released)) == urk, 'released-wrapper-does-not-open-original-urk')
        self.request('POST', P + '/unlock/finish', body, owner, expected=400)

    def memory_fixture(self, owner, blob_id):
        result = self.request('GET', '/pull?since=0', owner=owner)
        matches = [b for b in result['blobs'] if b['id'] == blob_id]
        check(len(matches) == 1, 'fixture-memory-not-unique')
        return matches[0]  # Do not compare global cursors during concurrent DEV activity.

    def run(self):
        self.checkpoint()
        self.preflight()
        a, b = self.register_account('a'), self.register_account('b')
        urk = secrets.token_bytes(32)
        original = self.vault(a, urk)
        self.vault(b, secrets.token_bytes(32))
        blob_id, nonce = self.namespace + '-memory', secrets.token_bytes(12)
        plaintext = b'synthetic trusted-browser acceptance fixture'
        ciphertext = AESGCM(urk).encrypt(nonce, plaintext, b'synthetic-memory-fixture')
        self.request('POST', '/push', {'id': blob_id, 'ciphertext': b64(ciphertext), 'nonce': b64(nonce),
            'updated_at': dt.datetime.now(dt.timezone.utc).isoformat()}, a)
        before = self.memory_fixture(a, blob_id)
        for phase in range(3):
            auth, envelope = Authenticator(), self.start(a)
            route = '/register/finish'
            credential = auth.register(envelope, uv=(phase != 0))
            if phase:
                envelope = self.advance(a, route, envelope, credential)
                route = '/register/test'
                if phase == 2:
                    envelope = self.advance(a, route, envelope, auth.assertion(envelope))
                    route = '/register/commit'
                credential = auth.assertion(envelope, uv=False)
            body = self.body(envelope, credential)
            if phase == 2:
                body['wrapper'] = self.fixture_wrapper()
            self.request('POST', P + route, body, a, expected=400)
            self.request('POST', P + route, body, a, expected=400)
        self.event('registration-and-both-assertions-require-uv')
        for phase in range(3):
            auth, envelope = Authenticator(), self.start(a)
            route, credential = '/register/finish', auth.register(envelope)
            for _ in range(phase):
                envelope = self.advance(a, route, envelope, credential)
                route = '/register/test' if route == '/register/finish' else '/register/commit'
                credential = auth.assertion(envelope)
            body = self.body(envelope, credential)
            if phase == 2:
                body['wrapper'] = self.fixture_wrapper()
            self.request('POST', P + '/cancel', {'ceremony_id': envelope['ceremony_id']}, a)
            self.request('POST', P + route, body, a, expected=400)
        check(self.request('GET', P, owner=a)['credentials'] == [], 'cancelled-enrollment-activated')
        self.event('all-enrollment-phase-cancellations')
        trusted, prf = self.enroll(a, urk), self.enroll(a, urk, 'prf')
        check(self.request('GET', '/api/self/vault', owner=a) == original, 'enrollment-changed-recovery-wrapper')
        self.unlock(a, trusted, urk)
        self.unlock(a, prf, urk)
        self.event('fresh-unlock-same-urk-and-prf-compatibility')
        enrollment, auth, _ = trusted
        self.request('POST', P + '/unlock/start', self.selector(enrollment), b, expected=400)
        self.request('POST', P + '/unlock/start', dict(self.selector(enrollment), device_id=str(uuid.uuid4())), a, expected=400)
        self.request('POST', P + '/unlock/start', {'credential_id': enrollment['credential_id']}, a, expected=400)
        session = self.request('POST', '/api/self/sessions', {'device_name': 'synthetic-second-session'}, a)
        a['sessions'].append(session['session_id'])
        envelope = self.unlock_start(a, enrollment)
        body = self.body(envelope, auth.assertion(envelope))
        self.request('POST', P + '/unlock/finish', body, b, expected=400)
        self.request('POST', P + '/unlock/finish', body, a, token=session['token'], expected=400)
        self.request('POST', P + '/unlock/finish', body, a)
        self.event('device-mode-account-session-ownership')
        cases = {'missing-uv': {'uv': False}, 'signed-wrong-origin': {'origin': 'https://sibling.dash.dev.rsrs.rs'},
            'signed-wrong-rp': {'rp': 'other.example.com'}, 'signed-wrong-challenge': {'challenge': b64(secrets.token_bytes(32))},
            'wrong-account-handle': {'account': b['account_id']}, 'wrong-device-finish': {}, 'wrong-mode-finish': {}}
        for name, changes in cases.items():
            envelope = self.unlock_start(a, enrollment)
            body = self.body(envelope, auth.assertion(envelope, **changes))
            if name == 'wrong-device-finish':
                body['device_id'] = str(uuid.uuid4())
            if name == 'wrong-mode-finish':
                body.pop('device_id')
                body['mode'] = 'prf'
            self.request('POST', P + '/unlock/finish', body, a, expected=400)
            self.request('POST', P + '/unlock/finish', self.body(envelope, auth.assertion(envelope)), a, expected=400)
            self.event(name + '-rejected-and-consumed')
        envelope = self.unlock_start(a, enrollment)
        self.request('POST', P + '/cancel', {'ceremony_id': envelope['ceremony_id']}, a)
        self.request('POST', P + '/unlock/finish', self.body(envelope, auth.assertion(envelope)), a, expected=400)
        self.request('POST', P + '/cancel', {'ceremony_id': enrollment['ceremony_id']}, a)
        self.unlock(a, trusted, urk)
        self.event('pending-cancel-does-not-rollback-committed-key')
        if self.args.include_expiry:
            envelope = self.unlock_start(a, enrollment)
            time.sleep(306)
            self.request('POST', P + '/unlock/finish', self.body(envelope, auth.assertion(envelope)), a, expected=400)
            self.event('five-minute-expiry')
        generation = original['key_generation']
        self.vault(a, urk, generation)
        self.unlock(a, trusted, urk)
        self.unlock(a, prf, urk)
        check(self.memory_fixture(a, blob_id) == before, 'rewrap-changed-ciphertext')
        check(AESGCM(urk).decrypt(nonce, ciphertext, b'synthetic-memory-fixture') == plaintext, 'memory-fixture-roundtrip')
        self.event('same-urk-rewrap-preserves-both-modes-and-memory')
        envelope = self.unlock_start(a, enrollment)
        pending = self.body(envelope, auth.assertion(envelope))
        new_urk = secrets.token_bytes(32)
        reset = self.vault(a, new_urk, generation, reset=True)
        check(reset['account_id'] == original['account_id'] and reset['key_generation'] == generation + 1, 'reset-generation-contract')
        check(self.request('GET', P, owner=a)['credentials'] == [], 'reset-left-old-credentials')
        self.request('POST', P + '/unlock/finish', pending, a, expected=400)
        self.request('POST', P + '/unlock/start', self.selector(prf[0]), a, expected=400)
        check(self.memory_fixture(a, blob_id) == before, 'reset-rewrote-old-ciphertext')
        try:
            AESGCM(new_urk).decrypt(nonce, ciphertext, b'synthetic-memory-fixture')
            raise Failure('new-urk-opened-old-ciphertext')
        except InvalidTag:
            pass
        self.event('destructive-reset-invalidates-both-modes-and-pending-generation')
        removable = self.enroll(a, new_urk)
        envelope = self.unlock_start(a, removable[0])
        body = self.body(envelope, removable[1].assertion(envelope))
        self.request('POST', P + '/remove', {'credential_id': removable[0]['credential_id']}, b, expected=400)
        self.request('POST', P + '/remove', {'credential_id': removable[0]['credential_id']}, a)
        self.request('POST', P + '/unlock/finish', body, a, expected=400)
        self.event('owned-removal-invalidates-pending-unlock')
        self.preflight()

    def cleanup(self):
        self.cleaning = True
        self.checkpoint()
        # Never purge accounts, delete memories or mutate an unverified token identity.
        for owner in self.accounts:
            if not owner['confirmed']:
                self.cleanup_events.append({'user': owner['user'], 'state': 'creation-outcome-unknown'})
                self.checkpoint()
                continue
            if not owner['identity_verified']:
                self.cleanup_events.append({'user': owner['user'], 'state': 'identity-unverified-cleanup-skipped'})
                self.checkpoint()
                continue
            incomplete = False

            def attempt(method, path, body=None, expected=200):
                nonlocal incomplete
                try:
                    return self.request(method, path, body, owner, expected=expected)
                except TotalDeadline:
                    raise
                except Exception:
                    # A failed optional removal must not strand bearer sessions.
                    # No retries and no exception details are logged.
                    incomplete = True
                    return None

            listing = attempt('GET', P)
            entries = listing.get('credentials') if isinstance(listing, dict) else None
            if not isinstance(entries, list):
                incomplete = True
            else:
                for entry in entries:
                    credential = entry.get('credential_id') if isinstance(entry, dict) else None
                    if not isinstance(credential, str) or not credential:
                        incomplete = True
                        continue
                    attempt('POST', P + '/remove', {'credential_id': credential})
            for account, ceremony in self.pending:
                if account is owner:
                    attempt('POST', P + '/cancel', {'ceremony_id': ceremony})
            for session in reversed(owner['sessions']):
                attempt('POST', '/api/self/sessions/' + urllib.parse.quote(session, safe='') + '/revoke', {})
            attempt('GET', '/api/self', expected=401)
            self.cleanup_events.append({'user': owner['user'], 'state': 'cleanup-incomplete-manual-review-required' if incomplete
                                        else 'passkeys-ceremonies-sessions-revoked-fixture-history-retained'})
            self.checkpoint()

    def report(self, failure):
        return {'ok': failure is None, 'failure_code': failure, 'source_revision_required': SHA, 'schema_required': 9,
            'schema_evidence': 'pinned-binary-ready-compares-database-version-to-current-schema', 'artifact_reconstructed': True,
            'local_only': self.args.local_test, 'limits': self.limits, 'request_diagnostics': self.request_diagnostics,
            'requests': self.requests, 'elapsed_seconds': round(time.monotonic()-self.started, 2),
            'checks_passed': self.events, 'expiry_requested': self.args.include_expiry, 'expiry_tested': 'five-minute-expiry' in self.events,
            'cleanup': self.cleanup_events, 'provider_browser_validation': 'not-covered-software-authenticator-only'}


def execute(runner, total_seconds=TOTAL_SECONDS, per_request=REQUEST_SECONDS):
    runner.limits.update(overall_seconds=total_seconds, request_seconds=per_request)
    failure = None
    try:
        with Deadlines(runner.started + total_seconds, per_request) as deadlines:
            runner.deadlines = deadlines
            try:
                runner.run()
            except TotalDeadline:
                raise
            except Failure as error:
                failure = str(error)
            except Exception:
                failure = 'unexpected-fixture-or-response-error-details-redacted'
            finally:
                if deadlines.expired or time.monotonic() >= deadlines.deadline:
                    raise TotalDeadline()
                runner.cleanup()
    except TotalDeadline as error:
        failure = str(error)
        reported = {event['user'] for event in runner.cleanup_events}
        for owner in runner.accounts:
            if owner['user'] not in reported:
                runner.cleanup_events.append({'user': owner['user'], 'state': 'deadline-interrupted-cleanup-manual-review-required'})
    except Failure as error:
        failure = str(error)
    if any(e['state'].endswith('manual-review-required') for e in runner.cleanup_events):
        failure = failure or 'cleanup-incomplete'
    if runner.journal_failed:
        failure = failure or 'public-journal-write-failed'
    runner.checkpoint(state='finished', failure=failure)
    if runner.journal_failed:
        failure = failure or 'public-journal-write-failed'
    return failure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default=DEV)
    parser.add_argument('--approve-synthetic-dev', action='store_true')
    parser.add_argument('--include-expiry', action='store_true', help='Wait 306 seconds and verify TTL rejection')
    parser.add_argument('--local-test', action='store_true', help='Only explicit 127.0.0.1 HTTP port; same immutable SHA required')
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--journal', type=Path, help='Public progress journal; defaults beside report')
    args = parser.parse_args()
    if args.journal is None:
        args.journal = args.report.with_name(args.report.name + '.progress.json')
    runner = Smoke(args)
    failure = execute(runner)
    atomic_json(args.report, runner.report(failure))
    print('PASS smoke-complete' if failure is None else 'FAIL ' + failure)
    return 0 if failure is None else 1


if __name__ == '__main__':
    sys.exit(main())
