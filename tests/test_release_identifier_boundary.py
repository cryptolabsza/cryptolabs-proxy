"""Exact public identifier vectors shared with the DC consumer by review evidence."""
import hashlib
import json

import pytest

from cryptolabs_proxy import release_selection as proxy


def pair(identifier, field):
    manifest = {'schema_version': 1, 'selection_contract': 1, 'baseline_id': 'synthetic-1',
                'components': {'prometheus': {'release': 'synthetic-1', 'owner': 'proxy-updater',
                'artifacts': {'linux/amd64': {'kind': 'oci', 'reference': 'prom/prometheus@sha256:'+'a'*64}}}}}
    selection = {'schema_version': 1, 'selection_id': 'synthetic-selection',
                 'manifest_sha256': '', 'components': {'prometheus': {'origin': 'baseline', 'enabled': True}}}
    if field == 'baseline_id': manifest['baseline_id'] = identifier
    elif field == 'release': manifest['components']['prometheus']['release'] = identifier
    else: selection['selection_id'] = identifier
    raw = json.dumps(manifest, indent=2).encode()
    selection['manifest_sha256'] = hashlib.sha256(raw).hexdigest()
    return json.dumps(selection, indent=2).encode(), raw


@pytest.mark.parametrize('field', ['baseline_id', 'selection_id', 'release'])
@pytest.mark.parametrize('identifier,accepted', [('a', True), ('a'*80, True), ('a'*81, False),
    ('a'*128, False), ('é', False), ('a\n', False), ('', False)])
def test_identifier_exact_boundary(field, identifier, accepted):
    selection, manifest = pair(identifier, field)
    if accepted:
        assert proxy.validate(selection, manifest)['selection_id']
    else:
        with pytest.raises(proxy.SelectionError): proxy.validate(selection, manifest)


def test_duplicate_identifier_field_rejected():
    selection, manifest = pair('valid', 'selection_id')
    selection = selection.replace(b'"selection_id": "valid"', b'"selection_id": "valid", "selection_id": "other"')
    with pytest.raises(proxy.SelectionError, match='duplicate_field'):
        proxy.validate(selection, manifest)
