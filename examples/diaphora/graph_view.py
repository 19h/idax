"""Materialize copied Diaphora models using opaque native graph objects."""
from idax import graph


class ModelCallback(graph.GraphCallback):
    def __init__(self, model):
        super().__init__()
        self.model = model
        self.closed = False

    def on_node_text(self, node):
        return self.model.nodes[node][1] if 0 <= node < len(self.model.nodes) else "ERROR"

    def on_node_color(self, node):
        return self.model.nodes[node][2] if 0 <= node < len(self.model.nodes) else 0x000000

    def on_destroyed(self):
        self.closed = True


def build_graph(model):
    """Build nodes/edges before display and retain copied callback text/colors."""
    value = graph.Graph()
    nodes = [value.add_node() for _ in model.nodes]
    for first, second in model.edges:
        if not (0 <= first < len(nodes) and 0 <= second < len(nodes)):
            raise ValueError("Graph model references an absent node")
        value.add_edge(nodes[first], nodes[second])
    return value, ModelCallback(model)
