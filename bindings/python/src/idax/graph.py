"""Custom graphs, viewers, flow charts, and switch tables."""

from ._native.graph import (
    BasicBlock,
    BlockType,
    Edge,
    EdgeInfo,
    Graph,
    GraphCallback,
    Layout,
    NodeInfo,
    SwitchTable,
    activate_graph_viewer,
    close_graph_viewer,
    flowchart,
    flowchart_for_ranges,
    has_graph_viewer,
    is_graph_viewer_visible,
    refresh_graph,
    show_graph,
    switch_table,
)

__all__ = [
    "BasicBlock", "BlockType", "Edge", "EdgeInfo", "Graph", "GraphCallback",
    "Layout", "NodeInfo", "SwitchTable", "activate_graph_viewer",
    "close_graph_viewer", "flowchart", "flowchart_for_ranges",
    "has_graph_viewer", "is_graph_viewer_visible", "refresh_graph",
    "show_graph", "switch_table",
]
