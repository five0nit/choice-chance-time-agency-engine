"""Unmapped ownership cannot establish host-root ownership."""
import os
from types import SimpleNamespace

import pytest
from cct_agent import cloud_backoff as cloud


@pytest.mark.parametrize('readonly,foreign_uid,foreign_leaf,writable_ancestor', [
    (True, 65534, False, False),
    (False, 65534, False, False),
    (True, 1234, False, False),
    (True, 65534, True, False),
    (True, 65534, False, True),
])
def test_unmapped_or_foreign_directory_fails_closed(
        monkeypatch, tmp_path, readonly, foreign_uid, foreign_leaf, writable_ancestor):
    root = tmp_path / 'ancestor'
    leaf = root / 'private'
    leaf.mkdir(parents=True, mode=0o700)
    root.chmod(0o755)
    original = os.fstat
    root_inode, leaf_inode = root.stat().st_ino, leaf.stat().st_ino

    def metadata(fd):
        result = original(fd)
        if result.st_ino == root_inode or foreign_leaf and result.st_ino == leaf_inode:
            values = list(result)
            values[4] = foreign_uid
            if writable_ancestor and result.st_ino == root_inode:
                values[0] = int(values[0]) | 0o020
            return os.stat_result(values)
        return result

    # Model the predecessor's recognized namespace. This injected helper is
    # deliberately unused by the strict implementation: the inferred UID is
    # not evidence that an unmapped host owner was actually root.
    monkeypatch.setattr(cloud, '_readonly_namespace_root', lambda fd: 65534, raising=False)
    monkeypatch.setattr(cloud.os, 'fstat', metadata)
    monkeypatch.setattr(cloud.os, 'fstatvfs', lambda fd: SimpleNamespace(f_flag=os.ST_RDONLY if readonly else 0))
    with pytest.raises(ValueError, match='CLOUD_RECOVERY_DIRECTORY_UNSAFE'):
        with cloud._shared_directory(leaf):
            pass


def test_visible_owner_directory_remains_accepted(tmp_path):
    leaf = tmp_path / 'private'
    leaf.mkdir(mode=0o700)
    with cloud._shared_directory(leaf) as fd:
        assert os.fstat(fd).st_ino == leaf.stat().st_ino


def test_unmapped_ancestor_cannot_alternate_private_leaves(monkeypatch, tmp_path):
    ancestor = tmp_path / 'unmapped'
    ancestor.mkdir(mode=0o755)
    for name in ['first', 'second']:
        (ancestor / name).mkdir(mode=0o700)
    original = os.fstat
    inode = ancestor.stat().st_ino

    def metadata(fd):
        result = original(fd)
        if result.st_ino == inode:
            values = list(result)
            values[4] = 65534
            return os.stat_result(values)
        return result

    monkeypatch.setattr(cloud, '_readonly_namespace_root', lambda fd: 65534, raising=False)
    monkeypatch.setattr(cloud.os, 'fstat', metadata)
    monkeypatch.setattr(cloud.os, 'fstatvfs', lambda fd: SimpleNamespace(f_flag=os.ST_RDONLY))
    for name in ['first', 'second']:
        with pytest.raises(ValueError, match='CLOUD_RECOVERY_DIRECTORY_UNSAFE'):
            with cloud._shared_directory(ancestor / name):
                pytest.fail('accepted an owner-only leaf beneath an unknown host owner')
