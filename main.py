#!/usr/bin/env python
"""Main module responsible for the attack graph generation pipeline."""

import sys
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor

from parsers import vulnerability_parser, attack_graph_parser, topology_parser
from mio import wrapper

__version__ = "1.0-dev4"


def main(argv):

    stat, config, examples, times = wrapper.init(argv)
    
    if stat != 0:
        return stat
    
    concurrency = config['nums-of-processes']
    if concurrency > 0:
        executor = ProcessPoolExecutor(concurrency, mp.get_context('forkserver'))
    else:
        executor = None
    
    attack_vectors = vulnerability_parser.get_attack_vectors(config["attack-vector-folder-path"], executor)
    
    for example in examples:
        example_folder, result_folder = wrapper.create_folders(example, config)
        if ret := parse_one_folder(example_folder, result_folder, config, attack_vectors, executor) != 0:
            return ret
    
    return 0


def parse_one_folder(example_folder: str, result_folder: str, config: dict, attack_vectors: dict[str, dict[str, ]],
                     executor: ProcessPoolExecutor):
    """
    Main function responsible for running the attack graph generations pipeline for multiple graphs.
    """
    
    networks, services, gateway_nodes, dt = topology_parser.parse_topology(example_folder)
    
    topology_graph, gateway_graph, gateway_graph_labels, dg = topology_parser.create_graphs(networks, services)
    
    print('\nTime for topology parser module:', dt + dg, 'seconds.')
    
    status, vulnerabilities, parsed_images, dv = vulnerability_parser.parse_vulnerabilities(example_folder, services)
    if status != 0:
        return status
    
    exploitable_vulnerabilities, scores, dvp = vulnerability_parser.get_exploitable_vulnerabilities(
        services, vulnerabilities, config["preconditions-rules"], config["postconditions-rules"], attack_vectors,
        config['single-edge-label'])
    
    print('\nTime for vulnerability parser module:', dv + dvp, 'seconds.')
    
    attack_graph, graph_labels, da = attack_graph_parser.\
        generate_attack_graph(networks, services, exploitable_vulnerabilities, scores, executor,
                              config['single-exploit-per-node'], config['single-edge-label'])
    
    composed_graph, composed_labels, dcg = attack_graph_parser.get_graph_compose(attack_graph, graph_labels)
    
    print('\nTime for attack graph generating module:', da + dcg, 'seconds.')
    
    # Printing time summary of the attack graph generation.
    wrapper.print_summary(topology_graph.number_of_nodes(),
                          topology_graph.number_of_edges(),
                          composed_graph.number_of_nodes(),
                          composed_graph.number_of_edges())
    
    if config['generate-graphs']:
        wrapper.visualise(topology_graph, gateway_graph, gateway_graph_labels,
                          composed_graph, composed_labels, result_folder, 0)
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
