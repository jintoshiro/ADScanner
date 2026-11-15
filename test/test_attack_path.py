import networkx as nx
from types import SimpleNamespace
from adscanner.checks.attack_path import CheckG1AttackPath
from adscanner.checks.base import ScanContext

def test_g1_finds_multistep_path():
    # Tạo đồ thị giả lập
    G = nx.MultiDiGraph()
    G.add_node("user1", type="user", name="g1_src")
    G.add_node("group1", type="group", name="g1_mid")
    G.add_node("user2", type="user", name="g1_dst")
    G.add_node("domain_admins", type="group", name="Domain Admins")
    G.add_node("domain", type="domain", name="Domain")
    
    # Cạnh: user1 -> group1 -> user2 -> Domain Admins
    G.add_edge("user1", "group1", relationship="MemberOf")
    G.add_edge("group1", "user2", relationship="WriteDacl")
    G.add_edge("user2", "domain_admins", relationship="MemberOf")
    
    ctx = ScanContext(
        profile=SimpleNamespace(primary=SimpleNamespace(domain_dn="DC=lab,DC=local")),
        connector=None,
        users=[
            SimpleNamespace(sid="user1", sam="g1_src", disabled=False),
            SimpleNamespace(sid="user2", sam="g1_dst", disabled=False),
        ],
        groups=[
            SimpleNamespace(sid="group1", sam="g1_mid", is_privileged=False),
            SimpleNamespace(sid="domain_admins", sam="Domain Admins", is_privileged=True),
        ],
        graph=G,
    )
    
    check = CheckG1AttackPath()
    result = check.run(ctx)
    assert result.status.value == "FAIL"
    assert "g1_src" in result.finding.affected_objects[0]["path"]