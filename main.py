#!/usr/bin/env python

#  Copyright 2022 Hanwen Zhang
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  Unless required by applicable law or agreed to in writing, software.
#  You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#  Distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import sys
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor

from layers.composed_graph_layer import ComposedGraphLayer
from layers.vulnerability_layer import VulnerabilityLayer
from layers.merged_graph_layer import MergedGraphLayer
from layers.attack_graph_layer import AttackGraphLayer
from layers.topology_layer import TopologyLayer

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
    
    attack_vectors = VulnerabilityLayer.get_attack_vectors(config["attack-vector-folder-path"], executor)
    
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
    
    topology_layer = TopologyLayer(example_folder)
    
    vulnerability_layer = VulnerabilityLayer(example_folder, topology_layer.services, config, attack_vectors)
    
    attack_graph_layer = AttackGraphLayer(vulnerability_layer, topology_layer, config, executor)
    
    composed_graph_layer = ComposedGraphLayer(attack_graph_layer)

    merged_graph_layer = MergedGraphLayer(topology_layer, vulnerability_layer, attack_graph_layer, composed_graph_layer)
    
    # Printing time summary of the attack graph generation.
    wrapper.print_summary(topology_layer.topology_graph.number_of_nodes(),
                          topology_layer.topology_graph.number_of_edges(),
                          composed_graph_layer.composed_graph.number_of_nodes(),
                          composed_graph_layer.composed_graph.number_of_edges())
    
    if config['generate-graphs']:
        wrapper.visualise(topology_layer, attack_graph_layer, composed_graph_layer,
                          merged_graph_layer, result_folder, 0)
    
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
