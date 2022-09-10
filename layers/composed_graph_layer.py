import time
import networkx as nx


def get_graph_compose(attack_graph: dict[str, nx.DiGraph],
                      graph_labels: dict[str, dict[((str, str), (str, str)), str]]) \
        -> (nx.DiGraph, dict[((str, str), (str, str)), str]):
    """This functions prints graph properties."""

    dcg = time.time()
    print('Composing attack graphs from subnets started.')

    if 'full' not in attack_graph:
        
        composed_labels: dict[((str, str), (str, str)), str] = dict()
    
        try:
            composed_graph: nx.DiGraph = nx.compose_all([*attack_graph.values()])
            
            for network in graph_labels:
                composed_labels |= graph_labels[network]
        except ValueError:
            composed_graph = nx.DiGraph()
    
    else:
        composed_graph = attack_graph['full']
        composed_labels = graph_labels['full']
        
    dcg = time.time() - dcg
    print('Time for composing subnets:', dcg, 'seconds.')
    return composed_graph, composed_labels, dcg


# noinspection PyCallingNonCallable
def remove_redundant(composed_graph: nx.DiGraph, composed_labels: dict[((str, str), (str, str)), str]):
    depth_delete_stack = []
    
    for node in composed_graph:
        
        if composed_graph.in_degree(node) == 0:
            print(node)
            (name, privilege) = node
            if name != 'outside':
                depth_delete_stack.append(node)
    print(depth_delete_stack)
    
    while len(depth_delete_stack) > 0:
        depth_first_remove(composed_graph, composed_labels, depth_delete_stack)


# noinspection PyCallingNonCallable
def depth_first_remove(composed_graph: nx.DiGraph, composed_labels: dict[((str, str), (str, str)), str],
                       depth_delete_stack: list[(str, str)]):

    node_to_remove = depth_delete_stack.pop()
    edges_to_remove = []
    end_nodes = set()
    
    out_edges = composed_graph.out_edges(node_to_remove)
    for out_edge in out_edges:
        (start_node, end_node) = out_edge
        edges_to_remove.append(out_edge)
        del composed_labels[out_edge]
        end_nodes.add(end_node)
    
    for end_node in end_nodes:
        
        if composed_graph.in_degree(end_node) == 0:
            depth_delete_stack.append(end_node)

    composed_graph.remove_node(node_to_remove)
