"""
Xây dựng đồ thị tấn công (Attack Graph) từ dữ liệu AD.
"""
import networkx as nx
import logging
from adscanner.utils.acl_mapper import classify_ace

logger = logging.getLogger(__name__)


def build_attack_graph(ctx) -> nx.MultiDiGraph:
    """Xây dựng đồ thị với SID làm node key, thêm cạnh MemberOf và ACL."""
    G = nx.MultiDiGraph()

    # Node đặc biệt
    G.add_node("S-1-1-0", type="special", name="Everyone")
    G.add_node("S-1-5-11", type="special", name="Authenticated Users")

    sid_to_dn = {}
    dn_to_sid = {}
    rid_to_sid = {}
    for g in ctx.groups:
        if g.sid:
            rid_to_sid[g.sid.split('-')[-1]] = g.sid
            dn_to_sid[g.dn.lower()] = g.sid

    # Users
    for u in ctx.users:
        if not u.sid:
            continue
        G.add_node(u.sid, type="user", name=u.sam, enabled=not u.disabled)
        sid_to_dn[u.sid] = u.dn
        dn_to_sid[u.dn.lower()] = u.sid
        G.add_edge(u.sid, "S-1-5-11", relationship="MemberOf")
        G.add_edge(u.sid, "S-1-1-0", relationship="MemberOf")
        # Primary Group
        if u.primary_group_id:
            pg_sid = rid_to_sid.get(str(u.primary_group_id))
            if pg_sid:
                G.add_edge(u.sid, pg_sid, relationship="MemberOf")

    # Groups
    for g in ctx.groups:
        if not g.sid:
            continue
        G.add_node(g.sid, type="group", name=g.sam)
        sid_to_dn[g.sid] = g.dn
        G.add_edge(g.sid, "S-1-5-11", relationship="MemberOf")
        G.add_edge(g.sid, "S-1-1-0", relationship="MemberOf")

    # Computers (nếu có)
    for c in ctx.computers:
        if hasattr(c, 'sid') and c.sid:
            G.add_node(c.sid, type="computer", name=c.sam)
            sid_to_dn[c.sid] = c.dn
            dn_to_sid[c.dn.lower()] = c.sid

    # Domain node
    domain_dn = ctx.profile.primary.domain_dn
    domain_sid = None
    if ctx.users and ctx.users[0].sid:
        domain_sid = "-".join(ctx.users[0].sid.split("-")[:-1])
        G.add_node(domain_sid, type="domain", name="Domain")

    # Cạnh MemberOf (dùng dn_to_sid để so sánh lowercase)
    for u in ctx.users:
        if not u.sid:
            continue
        for group_dn in u.member_of:
            target_sid = dn_to_sid.get(group_dn.lower())
            if target_sid:
                G.add_edge(u.sid, target_sid, relationship="MemberOf")

    for g in ctx.groups:
        if not g.sid:
            continue
        for parent_dn in g.member_of:
            target_sid = dn_to_sid.get(parent_dn.lower())
            if target_sid:
                G.add_edge(g.sid, target_sid, relationship="MemberOf")

    # Cạnh ACL (chỉ dùng ACE không inherit_only)
    for target_dn, acl in ctx.acls.items():
        # ĐÃ SỬA: dùng biến target_sid thay vì tgt_sid
        target_sid = dn_to_sid.get(target_dn.lower())
        if target_dn.lower() == domain_dn.lower():
            target_sid = domain_sid
        if not target_sid or not G.has_node(target_sid):
            continue

        for ace in acl.aces:
            if ace['type'] in (0x00, 0x05) and not ace['inherit_only']:
                src_sid = ace['sid']
                if not G.has_node(src_sid):
                    continue
                rights = classify_ace(ace, acl.target_label)
                for rel in rights:
                    G.add_edge(src_sid, target_sid, key=rel, relationship=rel)
    logger.info(f"[*] Đồ thị: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges.")
    return G