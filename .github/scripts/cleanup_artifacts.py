"""Delete only explicitly receipted, consumed Actions artifacts; stdlib + gh only."""
import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile
from urllib.parse import quote
from urllib.request import Request, HTTPRedirectHandler, build_opener
from urllib.error import HTTPError

RECEIPT = 'cleanup-ready-v1'
LIMIT = 1024 * 1024

def require(ok, message):
    if not ok:
        raise ValueError(message)

def moment(value):
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))

def identity(a):
    return {k: a[k] for k in ('id', 'name', 'size_in_bytes', 'digest', 'created_at')}

class GitHub:
    def request(self, path, method='GET', binary=False):
        require(path.startswith('repos/risense-ai/') and '..' not in path, 'invalid API scope')
        result = subprocess.run(['gh', 'api', '-X', method, path], capture_output=True, timeout=90)
        if result.returncode:
            if b'HTTP 404' in result.stderr:
                return {'already_absent': True} if method == 'DELETE' else None
            raise RuntimeError(f'GitHub {method} {path}: {result.stderr.decode()[:400]}')
        if binary:
            return result.stdout
        return json.loads(result.stdout) if result.stdout else None

    def pages(self, path, key):
        rows = []
        for page in range(1, 101):
            separator = '&' if '?' in path else '?'
            data = self.request(f'{path}{separator}per_page=100&page={page}')
            require(isinstance(data, dict) and isinstance(data.get(key), list), 'incomplete API listing')
            part = data[key]
            rows.extend(part)
            if len(part) < 100:
                return rows
        raise ValueError('pagination cap reached; refusing incomplete inventory')

    def tag_sha(self, repo, tag):
        ref = self.request(f'repos/{repo}/git/ref/tags/{quote(tag, safe="")}')
        require(ref is not None, 'publication tag missing')
        obj = ref['object']
        for _ in range(8):
            if obj['type'] == 'commit':
                return obj['sha']
            require(obj['type'] == 'tag', 'unexpected git object')
            obj = self.request(f'repos/{repo}/git/tags/{obj["sha"]}')['object']
        raise ValueError('tag nesting too deep')

    def receipt(self, repo, artifact):
        require(0 < artifact['size_in_bytes'] <= LIMIT, 'receipt archive too large')
        raw = self.request(f'repos/{repo}/actions/artifacts/{artifact["id"]}/zip', binary=True)
        require(raw is not None and len(raw) <= LIMIT, 'invalid receipt archive')
        require(artifact.get('digest') == 'sha256:' + hashlib.sha256(raw).hexdigest(), 'receipt archive digest mismatch')
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            require(len(entries) == 1 and entries[0].filename == 'cleanup-ready.json', 'unexpected receipt files')
            require(entries[0].file_size <= LIMIT and not entries[0].is_dir(), 'unbounded receipt content')
            return json.loads(archive.read(entries[0]))

    def release(self, repo, tag):
        r = self.request(f'repos/{repo}/releases/tags/{quote(tag, safe="")}')
        require(r is not None and not r['draft'] and r['tag_name'] == tag, 'release not public')
        assets = r['assets']
        # No partial embedded inventory: over 100 assets requires another protocol.
        require(0 < len(assets) < 100, 'empty or potentially truncated release inventory')
        require(all(a['size'] > 0 and re.fullmatch(r'sha256:[a-f0-9]{64}', a.get('digest') or '') for a in assets), 'release assets lack integrity metadata')
        return {'repository': repo, 'tag': tag, 'id': r['id'], 'sha': self.tag_sha(repo, tag),
                'published_at': r['published_at'], 'last_asset_update': max([r['published_at']] + [a['updated_at'] for a in assets]), 'assets': sorted([{'name': a['name'], 'size': a['size'], 'digest': a['digest']} for a in assets], key=lambda a: a['name'])}

    def public_bytes(self, url, limit):
        # Public registry only; never attach GitHub or registry credentials.
        require(url.startswith(('https://crates.io/api/v1/crates/', 'https://static.crates.io/crates/')), 'unexpected registry destination')
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        request = Request(url, headers={'User-Agent': 'respire-consumed-artifact-audit (https://github.com/risense-ai/respire-core)'})
        try:
            with build_opener(NoRedirect()).open(request, timeout=90) as response:
                raw = response.read(limit + 1)
                require(len(raw) <= limit, 'registry response exceeds audit limit')
                return raw
        except HTTPError as exc:
            raise ValueError(f'Native crate delivery unavailable: HTTP {exc.code}') from None

    def sdk_publication(self, sdk):
        name = 'respire-core-native-' + sdk['target']
        version = sdk['sdk_version']
        metadata = json.loads(self.public_bytes(f'https://crates.io/api/v1/crates/{name}/{version}', LIMIT))['version']
        require(metadata['num'] == version and not metadata['yanked'], 'native crate version is absent or yanked')
        checksum = metadata['checksum']
        require(re.fullmatch(r'[a-f0-9]{64}', checksum), 'invalid native crate checksum')
        cache = getattr(self, '_native_manifest_cache', {})
        if checksum not in cache:
            archive = self.public_bytes(f'https://static.crates.io/crates/{name}/{name}-{version}.crate', 64 * LIMIT)
            require(hashlib.sha256(archive).hexdigest() == checksum, 'native crate registry checksum mismatch')
            found, observed, total, count = [], {}, 0, 0
            with tarfile.open(fileobj=io.BytesIO(archive), mode='r|gz') as stream:
                for member in stream:
                    count += 1
                    total += member.size
                    require(count <= 30000 and total <= 512 * LIMIT, 'native crate archive bounds exceeded')
                    parts = member.name.split('/')
                    require(parts[0] == f'{name}-{version}' and all(p not in ('.', '..', '') for p in parts) and '\\' not in member.name, 'unsafe native crate path')
                    require(member.isfile() or member.isdir(), 'native crate link/special entry forbidden')
                    if member.name == f'{name}-{version}/native/manifest.json':
                        require(member.isfile() and member.size <= LIMIT, 'invalid native manifest size/type')
                        found.append(json.load(stream.extractfile(member)))
                    elif member.isfile() and member.name.startswith(f'{name}-{version}/native/'):
                        relative = member.name.removeprefix(f'{name}-{version}/native/')
                        if relative.startswith(('lib/', 'runtime/', 'include/')):
                            require(relative not in observed, 'duplicate native payload file')
                            digest = hashlib.sha256()
                            file = stream.extractfile(member)
                            while chunk := file.read(LIMIT):
                                digest.update(chunk)
                            observed[relative] = digest.hexdigest()
            require(len(found) == 1, 'native crate has no unique audited manifest')
            require({f['path']: f['sha256'] for f in native_files(found[0])} == observed and observed, 'native crate payload does not match its manifest')
            cache[checksum] = found[0]
            self._native_manifest_cache = cache
        # Immutable bytes may be cached by registry checksum, but each barrier
        # re-fetches version identity, yank status and delivery timestamps.
        return {'manifest': cache[checksum], 'published_at': metadata['created_at'], 'checksum': checksum}

class JsonGitHub(GitHub):
    """Producer stamps need only Python 3, including the private Core runner.

    Send the existing Actions token only to the fixed API host. Redirects are
    forbidden; this client never forwards credentials to a download hostname.
    """
    def request(self, path, method='GET', binary=False):
        require(path.startswith('repos/risense-ai/') and '..' not in path and method == 'GET' and not binary, 'producer API is read-only JSON')
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        request = Request('https://api.github.com/' + path, headers={
            'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
            'Accept': 'application/vnd.github+json', 'User-Agent': 'consumed-artifact-receipt-v1'}, method='GET')
        try:
            with build_opener(NoRedirect()).open(request, timeout=60) as response:
                raw = response.read(10 * LIMIT + 1)
                require(len(raw) <= 10 * LIMIT, 'API JSON response too large')
                return json.loads(raw)
        except HTTPError as exc:
            if exc.code == 404:
                return None
            raise RuntimeError(f'Producer API GET failed with HTTP {exc.code}') from None


def matching(policy, workflow, name):
    return any(re.fullmatch(pattern, name) for pattern in policy['workflows'][workflow]['artifacts'])

def validate_snapshot(policy, run, data):
    require(data['schema'] == 1 and data['policy'] == 'consumed-actions-v1', 'unsupported cleanup policy')
    require(data['repository'] == policy['repository'] == run['repository']['full_name'], 'foreign repository')
    require(run['path'] in policy['workflows'], 'unrecognized workflow')
    require(data['workflow'] == run['path'] and data['run_id'] == run['id'] and data['attempt'] == run['run_attempt'] and data['head_sha'] == run['head_sha'], 'receipt/source identity mismatch')
    require(run['head_repository']['full_name'] == policy['repository'] and run['event'] in ('push', 'workflow_dispatch', 'schedule'), 'untrusted source event')
    require(run['status'] == 'completed' and run['conclusion'] == 'success', 'source is not completed successfully')
    require(data['mode'] == policy['workflows'][run['path']]['mode'], 'receipt mode mismatch')
    require(data['artifacts'] and len({a['id'] for a in data['artifacts']}) == len(data['artifacts']), 'empty or duplicate artifact inventory')
    for a in data['artifacts']:
        require(isinstance(a['id'], int) and a['id'] > 0 and matching(policy, run['path'], a['name']), 'artifact outside allowlist')
        require(re.fullmatch(r'sha256:[a-f0-9]{64}', a['digest'] or ''), 'artifact lacks digest')

def native_files(manifest):
    return sorted([f for f in manifest['files'] if f['path'].startswith(('lib/', 'runtime/', 'include/'))], key=lambda f: f['path'])

def stamp(api, policy, output):
    Path(output).unlink(missing_ok=True)  # discard only this script's stale private-runner receipt
    repo = policy['repository']
    require(os.environ['GITHUB_REPOSITORY'] == repo, 'wrong runtime repository')
    run_id = int(os.environ['GITHUB_RUN_ID'])
    run = api.request(f'repos/{repo}/actions/runs/{run_id}')
    require(run['path'] in policy['workflows'], 'unsupported producer')
    require(run['event'] in ('push', 'workflow_dispatch', 'schedule') and run['head_repository']['full_name'] == repo, 'untrusted producer')
    config = policy['workflows'][run['path']]
    artifacts = api.pages(f'repos/{repo}/actions/runs/{run_id}/artifacts', 'artifacts')
    selected = [identity(a) for a in artifacts if not a['expired'] and matching(policy, run['path'], a['name'])]
    if not selected:
        print('No eligible artifacts; no cleanup receipt generated.')
        return
    data = {'schema': 1, 'policy': 'consumed-actions-v1', 'repository': repo, 'workflow': run['path'],
            'run_id': run_id, 'attempt': int(os.environ['GITHUB_RUN_ATTEMPT']), 'head_sha': run['head_sha'],
            'mode': config['mode'], 'created_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'artifacts': selected}
    if data['mode'] == 'release' or (data['mode'] == 'release-or-ci' and os.environ.get('CLEANUP_RELEASE_TAG')):
        tag = os.environ.get('CLEANUP_RELEASE_TAG', '')
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,150}', tag), 'missing exact published tag')
        data['publication'] = api.release(repo, tag)
        require(data['publication']['sha'] == os.environ.get('CLEANUP_SOURCE_SHA', run['head_sha']), 'published tag does not identify built source')
    elif data['mode'] == 'sdk':
        manifests = []
        for a in selected:
            target = a['name'].removeprefix('internal-core-sdk-')
            manifest = json.loads(Path('target/sdk', target, 'manifest.json').read_text())
            require(manifest['source_revision'] == run['head_sha'] and manifest['target'] == target and native_files(manifest), 'SDK provenance mismatch')
            manifests.append({'target': target, 'source_revision': manifest['source_revision'], 'sdk_version': manifest['sdk_version'], 'files': native_files(manifest)})
        require(len({m['sdk_version'] for m in manifests}) == 1, 'mixed SDK versions')
        data['sdk'] = manifests
    Path(output).write_text(json.dumps(data, indent=2) + '\n')
    print(f'Recorded {len(selected)} future opted-in artifacts. Receipt is not a deletion authorization until every consumer completes.')

def check(api, policy, run_id, receipt, data, now, own_run, acknowledged):
    repo = policy['repository']
    run = api.request(f'repos/{repo}/actions/runs/{run_id}')
    require(run is not None, 'source run disappeared')
    validate_snapshot(policy, run, data)
    live = api.pages(f'repos/{repo}/actions/runs/{run_id}/artifacts', 'artifacts')
    require([a['id'] for a in live if a['name'] == RECEIPT and not a['expired']] == [receipt['id']], 'ambiguous or missing receipt')
    jobs = api.pages(f'repos/{repo}/actions/runs/{run_id}/jobs?filter=latest', 'jobs')
    require(jobs and all(j['status'] == 'completed' and j['conclusion'] in ('success', 'skipped') for j in jobs), 'consumer job not successful/terminal')
    require(any(j['conclusion'] == 'success' for j in jobs), 'no successful producer jobs')
    # Conservatively block every active repository workflow. Completed unrelated
    # producers do not reset the clock forever (e.g. a 15-minute mirror cron).
    # Only explicit cross-workflow consumers reset the grace period.
    later = api.pages(f'repos/{repo}/actions/runs?created=>={quote(run["created_at"], safe="")}', 'workflow_runs')
    later = [r for r in later if r['id'] not in (own_run, run_id) and r['path'] not in ('.github/workflows/cleanup-artifacts.yml', '.github/workflows/cleanup-policy-tests.yml')]
    require(all(r['status'] == 'completed' for r in later), 'another repository consumer may still be running')
    times = [moment(run['updated_at']), moment(data['created_at']), moment(receipt['created_at'])]
    times += [moment(j['completed_at']) for j in jobs]
    # Same-run consumers are covered by jobs above; explicitly inventoried later
    # cross-workflow consumers start a fresh grace period too.
    consumer_paths = policy['workflows'][run['path']].get('consumer_workflows', [])
    times += [moment(r['updated_at']) for r in later if r['path'] in consumer_paths]
    if data['mode'] == 'release' or 'publication' in data:
        current = api.release(repo, data['publication']['tag'])
        require(current == data['publication'], 'public delivery identity/integrity changed')
        times.append(moment(current.get('last_asset_update', current['published_at'])))
    elif data['mode'] == 'sdk':
        expected = data['sdk']
        require(len(expected) == len(data['artifacts']), 'incomplete SDK proof')
        require(sorted(m['target'] for m in expected) == sorted(a['name'].removeprefix('internal-core-sdk-') for a in data['artifacts']), 'SDK targets do not match artifact inventory')
        require(all(m['source_revision'] == run['head_sha'] and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', m['sdk_version']) for m in expected), 'SDK source/version mismatch')
        for sdk in expected:
            delivered = api.sdk_publication(sdk)
            manifest = delivered['manifest']
            require(manifest['sdk_version'] == sdk['sdk_version'] and manifest['source_revision'] == sdk['source_revision'] and manifest['target'] == sdk['target'] and native_files(manifest) == sdk['files'], 'SDK was not delivered unchanged in its native crate')
            times.append(moment(delivered['published_at']))
    elif data['mode'] == 'external-delivery':
        require(acknowledged == run_id, 'operator delivery acknowledgment required; preserving unfinished input')
    require((now - max(times)).total_seconds() >= 3600, 'consumer grace period has not elapsed')
    expected_ids = {a['id'] for a in data['artifacts']} | {receipt['id']}
    require(all(a['id'] in expected_ids for a in live if matching(policy, run['path'], a['name'])), 'new artifact appeared after receipt')
    for a in data['artifacts'] + [identity(receipt)]:
        current = api.request(f'repos/{repo}/actions/artifacts/{a["id"]}')
        if current is not None:
            require(identity(current) == a and current['workflow_run']['id'] == run_id and not current['expired'], 'artifact identity changed')
    return run

def clean(api, policy, run_id, receipt, data, now, own_run=0, acknowledged=0, apply=False):
    check(api, policy, run_id, receipt, data, now, own_run, acknowledged)
    for artifact in data['artifacts'] + [identity(receipt)]:
        # Full source/consumer/publication/identity barrier before EVERY DELETE.
        check(api, policy, run_id, receipt, data, now, own_run, acknowledged)
        path = f'repos/{policy["repository"]}/actions/artifacts/{artifact["id"]}'
        current = api.request(path)
        if current is None:
            print(json.dumps({'id': artifact['id'], 'result': 'already-absent'}))
        elif apply:
            outcome = api.request(path, method='DELETE')  # never retry an uncertain DELETE
            if api.request(path) is not None:
                raise RuntimeError('delete not verified; stopping without retry')
            print(json.dumps({'id': artifact['id'], 'name': artifact['name'], 'result': 'already-absent-verified' if outcome == {'already_absent': True} else 'deleted-and-verified'}))
        else:
            print(json.dumps({'id': artifact['id'], 'name': artifact['name'], 'result': 'dry-run'}))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('stamp', 'clean'))
    parser.add_argument('--policy', default='.github/cleanup-policy.json')
    parser.add_argument('--output', default=os.environ.get('RUNNER_TEMP', '.') + '/cleanup-ready.json')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--consumed-run', type=int, default=0, help='Manual operator acknowledgment for an externally delivered input; never defaults to a run')
    args = parser.parse_args()
    policy = json.loads(Path(args.policy).read_text())
    require(os.environ['GITHUB_REPOSITORY'] == policy['repository'], 'wrong repository')
    api = GitHub()
    if args.command == 'stamp':
        stamp(JsonGitHub(), policy, args.output)
        return
    require(not args.consumed_run or os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'delivery acknowledgment must be an explicit manual dispatch')
    now = dt.datetime.now(dt.timezone.utc)
    for workflow in policy['workflows']:
        runs = api.pages(f'repos/{policy["repository"]}/actions/workflows/{workflow.rsplit("/", 1)[1]}/runs?status=completed&created=>={(now - dt.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")}', 'workflow_runs')
        if args.consumed_run and all(r['id'] != args.consumed_run for r in runs):
            explicit = api.request(f'repos/{policy["repository"]}/actions/runs/{args.consumed_run}')
            if explicit and explicit['path'] == workflow:
                runs.append(explicit)
        for run in runs:
            artifacts = api.pages(f'repos/{policy["repository"]}/actions/runs/{run["id"]}/artifacts', 'artifacts')
            receipts = [a for a in artifacts if a['name'] == RECEIPT and not a['expired']]
            if not receipts:
                continue  # Explicit opt-in only. No historical sweep.
            require(len(receipts) == 1, 'duplicate receipt; stop')
            data = api.receipt(policy['repository'], receipts[0])
            try:
                clean(api, policy, run['id'], receipts[0], data, now, int(os.environ['GITHUB_RUN_ID']), args.consumed_run, args.apply)
            except ValueError as exc:
                print(json.dumps({'run_id': run['id'], 'result': 'preserved', 'reason': str(exc)}))
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
            summary.write('Cleanup audit is in the job log. Only receipted consumed Actions artifacts are eligible; official release assets, tags, packages, images and caches are outside this API scope.\n')

if __name__ == '__main__':
    main()
