"""Data model for simple link-list topology YAML."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TopologyLink:
    device_a: str
    port_a: str
    device_b: str
    port_b: str


@dataclass
class Topology:
    devices: list[str]
    links: list[TopologyLink]

    def adjacency(self) -> dict[str, list[str]]:
        graph: dict[str, list[str]] = {d: [] for d in self.devices}
        for link in self.links:
            graph[link.device_a].append(link.device_b)
            graph[link.device_b].append(link.device_a)
        return graph
