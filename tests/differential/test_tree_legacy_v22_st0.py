from sigma.anchors.tree_wide import TreeWide
from sigma.presets import simultaneous_v2_2
from sigma.tree import TreeRoot
from sigma.tree.legacy_v22 import compute_v22_treewide, is_sigma_tree_v1_root


def test_legacy_adapter_is_read_only_and_byte_exact():
    context = simultaneous_v2_2()
    chunks = [b"a" * 17, b"b" * 70_000, b"c" * 9]
    direct = TreeWide.compute(context, chunks)
    adapted = compute_v22_treewide(context, chunks)
    assert adapted.to_bytes() == direct.to_bytes()
    assert not is_sigma_tree_v1_root(adapted)
    assert not isinstance(adapted, TreeRoot)
