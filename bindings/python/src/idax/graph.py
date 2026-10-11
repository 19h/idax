"""Custom graphs, viewers, flow charts, and switch tables.

Displayed graphs and optional user callbacks remain rooted until terminal
viewer closure, including manual window closure. A successful close request
can return before that notification. Live or pending viewer titles cannot be
replaced; reuse a title after its viewer has closed.
"""

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
    SwitchCase,
    activate_graph_viewer,
    close_graph_viewer,
    flowchart,
    flowchart_for_ranges,
    has_graph_viewer,
    is_graph_viewer_visible,
    refresh_graph,
    show_graph,
    switch_table,
    switch_cases,
)

__all__ = [
    "BasicBlock", "BlockType", "Edge", "EdgeInfo", "Graph", "GraphCallback",
    "Layout", "NodeInfo", "SwitchTable", "SwitchCase", "activate_graph_viewer",
    "close_graph_viewer", "flowchart", "flowchart_for_ranges",
    "has_graph_viewer", "is_graph_viewer_visible", "refresh_graph",
    "show_graph", "switch_table", "switch_cases",
]
