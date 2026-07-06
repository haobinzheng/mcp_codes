"""Place devices on a canvas for diagram export."""

from __future__ import annotations

from dataclasses import dataclass

from topology_model import Topology


@dataclass(frozen=True)
class NodeLayout:
    device: str
    x: float
    y: float
    width: float
    height: float

    @property
    def center_x(self) -> float:
        return self.x + self.width / 2

    @property
    def center_y(self) -> float:
        return self.y + self.height / 2

    @property
    def right_x(self) -> float:
        return self.x + self.width

    @property
    def left_x(self) -> float:
        return self.x


@dataclass(frozen=True)
class TopologyLayout:
    nodes: dict[str, NodeLayout]
    canvas_width: float
    canvas_height: float


NODE_WIDTH = 180.0
NODE_HEIGHT = 72.0
H_GAP = 120.0
V_GAP = 100.0
MARGIN = 48.0


def _order_devices_as_path(topology: Topology) -> list[str] | None:
    """Return a left-to-right order when the graph is a simple path; else None."""
    if not topology.links:
        return list(topology.devices)

    graph = topology.adjacency()
    degrees = {d: len(graph[d]) for d in topology.devices}
    endpoints = [d for d, deg in degrees.items() if deg == 1]
    if len(endpoints) != 2:
        return None

    order = [endpoints[0]]
    visited = {order[0]}
    while len(order) < len(topology.devices):
        current = order[-1]
        neighbors = [n for n in graph[current] if n not in visited]
        if len(neighbors) != 1:
            return None
        order.append(neighbors[0])
        visited.add(neighbors[0])
    return order


def _order_devices_bfs(topology: Topology) -> list[str]:
    graph = topology.adjacency()
    start = topology.devices[0]
    order: list[str] = []
    seen: set[str] = set()
    queue = [start]
    while queue:
        node = queue.pop(0)
        if node in seen:
            continue
        seen.add(node)
        order.append(node)
        for neighbor in sorted(graph[node]):
            if neighbor not in seen:
                queue.append(neighbor)
    for device in topology.devices:
        if device not in seen:
            order.append(device)
    return order


def layout_topology(topology: Topology) -> TopologyLayout:
    order = _order_devices_as_path(topology) or _order_devices_bfs(topology)
    nodes: dict[str, NodeLayout] = {}
    for i, device in enumerate(order):
        x = MARGIN + i * (NODE_WIDTH + H_GAP)
        y = MARGIN + (NODE_HEIGHT + V_GAP) * (i % 2) * 0  # single row for paths
        nodes[device] = NodeLayout(device=device, x=x, y=y, width=NODE_WIDTH, height=NODE_HEIGHT)

    max_x = max(n.right_x for n in nodes.values())
    max_y = max(n.y + n.height for n in nodes.values())
    return TopologyLayout(
        nodes=nodes,
        canvas_width=max_x + MARGIN,
        canvas_height=max_y + MARGIN,
    )
