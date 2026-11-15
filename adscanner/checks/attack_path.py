import networkx as nx
from collections import Counter
from adscanner.checks.base import BaseCheck, ScanContext, Severity, Finding
from adscanner.checks.registry import register

CATEGORY = "Attack Path"
MAX_DEPTH = 6

def _edge_label(G, a, b):
    data = G.get_edge_data(a, b) or {}
    return '/'.join(sorted({d['relationship'] for d in data.values()}))

@register
class CheckG1AttackPath(BaseCheck):
    id = "G1"
    name = "Đường tấn công leo thang đặc quyền"
    category = CATEGORY
    severity = Severity.CRITICAL
    description = (
        "Tìm các đường đi từ user thường tới nhóm đặc quyền hoặc Domain object. "
        "Đồ thị sử dụng thuật toán BFS để đảm bảo tìm ra con đường ít bước nhất."
    )
    remediation = "Gỡ bỏ các ACE thừa hoặc xóa user khỏi nhóm không cần thiết dọc theo đường tấn công."

    def _check(self, ctx: ScanContext) -> Finding | None:
        G = getattr(ctx, "graph", None)
        if G is None: return None

        domain_sid = next((n for n, d in G.nodes(data=True) if d.get('type') == 'domain'), None)
        if not domain_sid: return None

        # 1. Xác định Đích (Targets)
        priv_groups = {g.sid for g in ctx.groups if g.is_privileged}
        targets = {domain_sid} | priv_groups

        # 2. Xác định Nguồn (Sources)
        M = nx.DiGraph((a, b) for a, b, d in G.edges(data=True) if d['relationship'] == 'MemberOf')
        privileged_nodes = set(priv_groups)
        for t in priv_groups:
            if t in M:
                privileged_nodes |= nx.ancestors(M, t)
        sources = {u.sid for u in ctx.users if not u.disabled and u.sid not in privileged_nodes}

        # 3. Kỹ thuật Virtual Target Node (Tối ưu BFS)
        TARGET_NODE = "__VIRTUAL_TARGET__"
        G.add_node(TARGET_NODE)
        for t in targets:
            if G.has_node(t):
                G.add_edge(t, TARGET_NODE)

        R = G.reverse(copy=False)
        paths_to_target = nx.single_source_shortest_path(R, TARGET_NODE, cutoff=MAX_DEPTH + 1)

        affected, choke = [], Counter()
        for src_sid, path_reversed in paths_to_target.items():
            if src_sid not in sources or src_sid == TARGET_NODE: continue
            
            path = list(reversed(path_reversed))
            path = path[:-1] # Bỏ node ảo TARGET_NODE ra khỏi cuối
            
            labels = [_edge_label(G, a, b) for a, b in zip(path, path[1:])]
            
            # Bỏ qua đường 1 bước DCSync (đã có A8 bắt)
            if len(path) == 2 and labels[0] == 'DCSync': continue
            
            steps = [f"{G.nodes[a]['name']} --[{l}]--> {G.nodes[b]['name']}"
                     for a, b, l in zip(path, path[1:], labels)]
            
            for a, b, l in zip(path, path[1:], labels):
                if l != 'MemberOf':
                    choke[(G.nodes[a]['name'], l, G.nodes[b]['name'])] += 1
                    
            affected.append({
                "source": G.nodes[src_sid]['name'], 
                "steps": len(path) - 1,
                "path": " ; ".join(steps)
            })

        if not affected: return None
        
        affected.sort(key=lambda x: x["steps"])
        top_choke = choke.most_common(5)
        choke_str = "; ".join([f"{s} --[{r}]--> {t} (chặn {c} đường)" for (s, r, t), c in top_choke])
        
        summary = f"Phát hiện {len(affected)} đường tấn công. Các điểm nghẽn (Choke points): {choke_str}"
        return self._make_finding(affected[:10], summary)