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

"""
Main module that builds a pipeline for multiple experiments. For details, please see main.ipydb
"""

import sys
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor

from layers.composed_graph_layer import ComposedGraphLayer
from layers.vulnerability_layer import VulnerabilityLayer
from layers.merged_graph_layer import MergedGraphLayer
from layers.attack_graph_layer import AttackGraphLayer
from layers.topology_layer import TopologyLayer

from mio import wrapper

__version__ = "1.0-dev5"


def main(argv):
    """
    Main function responsible for running the attack graph generations pipeline for multiple graphs.
    Parameters:
        argv: sys.argv
    """
    config, examples = wrapper.init(argv)
    
    concurrency = config['nums-of-processes']
    if concurrency > 0:
        executor = ProcessPoolExecutor(concurrency, mp.get_context('forkserver'))
    else:
        executor = None
    
    attack_vectors = VulnerabilityLayer.get_attack_vectors(config["attack-vector-folder-path"], executor)
    
    for example in examples:
        example_folder, result_folder = wrapper.create_folders(example, config)
        parse_one_folder(example_folder, result_folder, config, attack_vectors, executor)
    
    return 0


def parse_one_folder(example_folder: str, result_folder: str, config: dict, attack_vectors: dict[str, dict[str]],
                     executor: ProcessPoolExecutor):
    """
    Creating layers of one example folder, then test honeypot deployments.
    Parameters:
        example_folder:
        result_folder:
        config: config.yml file in form of dictionary
        attack_vectors: result of VulnerabilityLayer.get_attack_vectors()
        executor: concurrent.futures.Executor, default: None
    """
    
    # get topology layer
    topology_layer = TopologyLayer(example_folder)
    
    # get vulnerability layer
    vulnerability_layer = VulnerabilityLayer(topology_layer, config, attack_vectors)
    
    # get attack graph layer
    attack_graph_layer = AttackGraphLayer(vulnerability_layer, executor)
    
    # get composed graph layer
    composed_graph_layer = ComposedGraphLayer(attack_graph_layer)
    
    # get merged graph layer
    merged_graph_layer = MergedGraphLayer(composed_graph_layer)
    
    # Printing time summary of the attack graph generation.
    wrapper.print_summary(merged_graph_layer)
    
    if config['generate-graphs']:
        # draw graphs
        wrapper.visualise(merged_graph_layer, result_folder, 0)


if __name__ == '__main__':
    # All magics start from here...
    sys.exit(main(sys.argv))
