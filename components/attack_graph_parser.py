#!/usr/bin/env python
"""Module responsible for generating the attack graph."""

import time
import networkx
from queue import Queue
from components import reader
from components import topology_parser


def clean_vulnerabilities(raw_vulnerabilities, container):
    """Cleans the vulnerabilities for a given container."""
    
    vulnerabilities = {}
    
    # Going to the .json hierarchy to get the CVE ids.
    layers = raw_vulnerabilities["Layers"]
    for layer in layers:
        features = layer["Layer"]["Features"]
        for feature in features:
            if "Vulnerabilities" not in feature:
                continue
            
            vulnerabilities_structure = feature["Vulnerabilities"]
            for vulnerability in vulnerabilities_structure:
                vulnerability_new = {}
                
                # Finding the description
                if "Description" in vulnerability.keys():
                    vulnerability_new["desc"] = vulnerability["Description"]
                else:
                    vulnerability_new["desc"] = "?"
                
                # Finding the attack vector
                vulnerability_new["attack_vec"] = "?"
                if "Metadata" in vulnerability.keys():
                    metadata = vulnerability["Metadata"]
                    if "NVD" not in metadata:
                        continue
                    
                    if "CVSSv2" not in metadata["NVD"]:
                        continue
                    
                    cvss_v2 = metadata["NVD"]["CVSSv2"]
                    if "Vectors" in cvss_v2:
                        vec = cvss_v2["Vectors"]
                        vulnerability_new["attack_vec"] = vec
                vulnerabilities[vulnerability["Name"]] = vulnerability_new
    
    print("Total " + str(len(vulnerabilities)) + " vulnerabilities in container " + container + ".")
    
    return vulnerabilities


def get_graph(attack_paths):
    """Getting the nodes and edges for an array of attack paths."""
    
    # Initializing the nodes and edges arrays.
    nodes = []
    edges = {}
    
    # Generating unique nodes.
    for attack_path in attack_paths:
        for node in attack_path:
            if node not in nodes:
                nodes.append(node)
    
    # Generating unique edges.
    for attack_path in attack_paths:
        
        # Checking if an edge is present.
        if len(attack_path) >= 2:
            for i in range(1, len(attack_path)):
                key = attack_path[i] + "|" + attack_path[i - 1]
                edges[key] = [attack_path[i], attack_path[i - 1]]
    
    return nodes, edges


def get_attack_vector(attack_vector_files):
    """Merging the attack vector files into a dictionary."""
    
    # Initializing the attack vector dictionary.
    attack_vector_dict = {}
    
    count = 0
    # Iterating through the attack vector files.
    for attack_vector_file in attack_vector_files:
        
        # Load the attack vector.
        cve_items = attack_vector_file["CVE_Items"]
        
        # Filtering only the important information and creating the dictionary.
        for cve_item in cve_items:
            dictionary_cve = {"attack_vec": "?", "desc": "?", "cpe": "?"}
            # Getting the attack vector and the description.
            if "baseMetricV2" in cve_item["impact"]:
                
                cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
                
                cve_attack_vector = cve_item["impact"]["baseMetricV2"]["cvssV2"]["vectorString"]
                dictionary_cve["attack_vec"] = cve_attack_vector
                
                if "description" in cve_item["cve"]:
                    descr = cve_item["cve"]["description"]["description_data"][0]['value']
                    dictionary_cve["desc"] = descr
            else:
                cve_id = None
            
            # Get the CPE values: a - application, o - operating system and h - hardware
            nodes = cve_item["configurations"]["nodes"]
            if len(nodes) > 0:
                if "cpe" in nodes[0]:
                    cpe = cve_item["configurations"]["nodes"][0]["cpe"][0]["cpe22Uri"]
                    dictionary_cve["cpe"] = cpe
                    count = count + 1
                else:
                    if "children" in nodes[0]:
                        children = nodes[0]["children"]
                        if len(children) > 0 and "cpe" in children[0]:
                            cpe = children[0]["cpe"][0]["cpe22Uri"]
                            dictionary_cve["cpe"] = cpe
                            count = count + 1
            
            if dictionary_cve["cpe"] != "?":
                dictionary_cve["cpe"] = dictionary_cve["cpe"][5]
            attack_vector_dict[cve_id] = dictionary_cve
    return attack_vector_dict


def add_edge(nodes, edges, node_start, node_start_privilege, node_end, node_end_privilege, edge_desc, passed_edges):
    """
    Adding an edge to the attack graph and checking if nodes already exist.
    """
    
    """for key in edges.keys():
        if key.endswith(node_start):
            container = node_end.split("(")[0]
            if key.startswith(container):
                return nodes, edges, passed_edges"""
    
    # Checks if the opposite edge is already in the collection. If it is, don't add the edge.
    node_start_full = node_start + "(" + node_start_privilege + ")"
    node_end_full = node_end + "(" + node_end_privilege + ")"
    
    node = passed_edges.get(node_end + "|" + node_start_full)
    if node is None:
        passed_edges[node_start + "|" + node_end_full] = True
    else:
        return nodes, edges, passed_edges
    
    if node_start_full not in nodes:
        nodes.add(node_start_full)
    
    if node_end_full not in nodes:
        nodes.add(node_end_full)
    
    key = node_start_full + "|" + node_end_full
    
    edge = edges.get(key)
    if edge is None:
        edges[key] = [edge_desc]
    else:
        edge.append(edge_desc)
        edges[key] = edge
    
    return nodes, edges, passed_edges


def breadth_first_search(topology, container_exploit_ability):
    """Breadth first search approach for generation of nodes and edges
    without generating attack paths."""
    
    # This is where the nodes and edges are going to be stored.
    edges = {}
    nodes = set()
    passed_nodes = {}
    passed_edges = {}
    
    # Putting the attacker in the queue
    queue = Queue()
    queue.put("outside|4")
    passed_nodes["outside|4"] = True
    
    # Starting the time
    bds_start = time.time()
    
    while not queue.empty():
        
        parts_current = queue.get().split("|")
        current_node = parts_current[0]
        current_privilege = int(parts_current[1])
        
        neighbours = topology[current_node]
        neighbours.append(current_node)
        
        # Iterate through all of neighbours
        for neighbour in neighbours:
            
            # Checks if the attacker has access to the docker host.
            if neighbour != "outside":
                pre_conditions = container_exploit_ability[neighbour]["precond"]
                post_conditions = container_exploit_ability[neighbour]["postcond"]
                
                for vulnerability in pre_conditions.keys():
                    
                    if current_privilege >= pre_conditions[vulnerability] and \
                            ((neighbour != current_node and post_conditions[vulnerability] != 0) or
                             (neighbour == current_node and current_privilege < post_conditions[vulnerability])):
                        
                        # Add the edge
                        nodes, edges, passed_edges = add_edge(nodes,
                                                              edges,
                                                              current_node,
                                                              get_privilege_level(current_privilege),
                                                              neighbour,
                                                              get_privilege_level(post_conditions[vulnerability]),
                                                              vulnerability,
                                                              passed_edges)
                        
                        # If the neighbour was not passed, or it has a lower privilege...
                        passed_nodes_key = neighbour + "|" + str(post_conditions[vulnerability])
                        if passed_nodes.get(passed_nodes_key) is None:
                            # ... put it in the queue
                            queue.put(passed_nodes_key)
                            passed_nodes[passed_nodes_key] = True
    
    duration_bdf = time.time() - bds_start
    print("Breadth-first-search took " + str(duration_bdf) + " seconds.")
    return nodes, edges, duration_bdf


def attack_vector_string_to_dict(av_string):
    """Transforms the attack vector string to dictionary."""
    
    av_dict = {}
    
    # Remove brackets.
    if av_string[0] == "(":
        av_string = av_string[1:len(av_string) - 1]
    
    # Put structure into dictionary
    categories = av_string.split("/")
    for category in categories:
        parts = category.split(":")
        av_dict[parts[0]] = parts[1]
    
    return av_dict


def merge_attack_vector_vulnerabilities(attack_vector_dict, vulnerabilities):
    """Merging the information from vulnerabilities and the attack vector files."""
    
    merged_vulnerabilities = {}
    
    for vulnerability in vulnerabilities:
        vulnerability_new = {}
        
        if vulnerability in attack_vector_dict:
            
            vulnerability_new["desc"] = attack_vector_dict[vulnerability]["desc"]
            
            if attack_vector_dict[vulnerability]["attack_vec"] != "?":
                av_string = attack_vector_dict[vulnerability]["attack_vec"]
                attack_vec = attack_vector_string_to_dict(av_string)
                vulnerability_new["attack_vec"] = attack_vec
            vulnerability_new["cpe"] = attack_vector_dict[vulnerability]["cpe"]
        
        else:
            
            vulnerability_new["desc"] = vulnerabilities[vulnerability]["desc"]
            if vulnerabilities[vulnerability]["attack_vec"] != "?":
                av_string = vulnerabilities[vulnerability]["attack_vec"]
                attack_vec = attack_vector_string_to_dict(av_string)
                vulnerability_new["attack_vec"] = attack_vec
            
            vulnerability_new["cpe"] = "?"
        
        merged_vulnerabilities[vulnerability] = vulnerability_new
    
    return merged_vulnerabilities


def get_value(privilege):
    """Mapping the privilege level to its value, so that it can be compared later."""
    
    mapping = {"NONE": 0, "VOS USER": 1, "VOS ADMIN": 2, "USER": 3, "ADMIN": 4}
    
    return mapping[privilege]


def get_privilege_level(privilege):
    """Mapping the value to the privilege level for easier readability in the attack graph."""
    
    mapping = {0: "NONE", 1: "VOS USER", 2: "VOS ADMIN", 3: "USER", 4: "ADMIN"}
    
    return mapping[privilege]


def get_rule_precondition(rule, vulnerability, pre_conditions, vulnerability_key):
    """Checks if it finds rule precondition"""
    
    # Checks if the cpe in the rule is same with vulnerability.
    if rule["cpe"] != "?":
        if rule["cpe"] == "o" and vulnerability["cpe"] != "o":
            return pre_conditions
        elif rule["cpe"] == "h" and (vulnerability["cpe"] != "h" and vulnerability["cpe"] != "a"):
            return pre_conditions
    
    # Checks if the vocabulary is matching
    if "vocabulary" in rule.keys():
        is_hit = is_hit_vocabulary(rule, vulnerability)
        pre_value = get_value(rule["precondition"])
        if is_hit and (vulnerability_key not in pre_conditions or pre_conditions[vulnerability_key] < pre_value):
            pre_conditions[vulnerability_key] = pre_value
    
    # Check access vector
    else:
        
        attack_vec_av = vulnerability["attack_vec"]["AV"]
        attack_vec_au = vulnerability["attack_vec"]["Au"]
        
        if rule["accessVector"] != "?":
            
            if rule["accessVector"] == "LOCAL" and attack_vec_av != "L":
                return pre_conditions
            elif attack_vec_av != "A" and attack_vec_av != "N":
                return pre_conditions
        
        if rule["authentication"] != "?":
            if rule["authentication"] == "NONE" and attack_vec_au != "N":
                return pre_conditions
            elif attack_vec_au != "L" and attack_vec_au != "H":
                return pre_conditions
        
        pre_value = get_value(rule["precondition"])
        
        if rule["accessComplexity"][0] == vulnerability["attack_vec"]["AC"] and \
                (vulnerability_key not in pre_conditions or pre_conditions[vulnerability_key] < pre_value):
            pre_conditions[vulnerability_key] = pre_value
    
    return pre_conditions


def get_post_condition_from_rule(rule, vulnerability, post_condition, vulnerability_key):
    """Checks if it finds rule post-condition"""
    
    # Checks if the cpe in the rule is same with vulnerability.
    rule_cpe = rule["cpe"]
    vulnerability_cpe = vulnerability["cpe"]
    
    if rule_cpe != "?":
        if rule_cpe == "o" and vulnerability_cpe != "o":
            return post_condition
        elif rule_cpe == "h" and (vulnerability_cpe != "h" and vulnerability_cpe != "a"):
            return post_condition
    
    # Checks if the vocabulary is matching
    hit_vocabulary = is_hit_vocabulary(rule, vulnerability)
    if not hit_vocabulary:
        return post_condition
    
    # Check Impacts
    impacts = rule["impacts"]
    attack_vector_i = vulnerability["attack_vec"]["I"]
    attack_vector_c = vulnerability["attack_vec"]["C"]
    post_condition_value = get_value(rule["postcondition"])
    
    if impacts == "ALL_COMPLETE":
        if attack_vector_i == "C" and attack_vector_c == "C":
            if vulnerability_key not in post_condition or post_condition[vulnerability_key] > post_condition_value:
                post_condition[vulnerability_key] = post_condition_value
    
    elif impacts == "PARTIAL":
        
        if attack_vector_i == "P" or attack_vector_c == "P":
            if vulnerability_key not in post_condition or post_condition[vulnerability_key] > post_condition_value:
                post_condition[vulnerability_key] = post_condition_value
        
        else:
            if vulnerability_key not in post_condition or post_condition[vulnerability_key] > post_condition_value:
                post_condition[vulnerability_key] = post_condition_value
    
    elif impacts == "ANY_NONE":
        if attack_vector_i or attack_vector_c == "N":
            if vulnerability_key not in post_condition or post_condition[vulnerability_key] > post_condition_value:
                post_condition[vulnerability_key] = post_condition_value
    
    return post_condition


def is_hit_vocabulary(rule, vulnerability):
    sentences = rule["vocabulary"]
    hit_vocabulary = False
    description = vulnerability["desc"]
    for sentence in sentences:
        if "..." in sentence:
            parts = sentence.split("...")
            if parts[0] in description and parts[1] in description:
                hit_vocabulary = True
                break
        elif "?" == sentence:
            hit_vocabulary = True
            break
        elif sentence in description:
            hit_vocabulary = True
            break
    return hit_vocabulary


def rule_processing(merged_vulnerabilities, pre_rules, post_rules):
    """ This function is responsible for creating the
    precondition and post-condition rules."""
    
    pre_condition = {}
    post_condition = {}
    for vulnerability_key in merged_vulnerabilities:
        vulnerability = merged_vulnerabilities[vulnerability_key]
        
        if "attack_vec" not in vulnerability or vulnerability["attack_vec"] == "?":
            continue
        for pre_rule in pre_rules:
            rule = pre_rules[pre_rule]
            pre_condition = get_rule_precondition(rule, vulnerability, pre_condition, vulnerability_key)
        
        for post_rule in post_rules:
            rule = post_rules[post_rule]
            post_condition = get_post_condition_from_rule(rule, vulnerability, post_condition, vulnerability_key)
        
        # Assign default values if rules are undefined
        if vulnerability_key not in pre_condition:
            pre_condition[vulnerability_key] = 0  # 0 is None level
        if vulnerability_key not in post_condition:
            post_condition[vulnerability_key] = 4  # 4 is Admin level
    
    return pre_condition, post_condition


def get_container_exploitable_vulnerabilities(vulnerabilities, container, attack_vector_dict, pre_rules, post_rules):
    """Processes and provides exploitable vulnerabilities per container."""
    
    # Remove junk and just take the most important part from each vulnerability
    cleaned_vulnerabilities = clean_vulnerabilities(vulnerabilities, container)
    
    # Merging the cleaned vulnerabilities
    merged_vulnerabilities = merge_attack_vector_vulnerabilities(attack_vector_dict, cleaned_vulnerabilities)
    
    # Get the preconditions and postconditions for each vulnerability.
    pre_conditions, post_conditions = rule_processing(merged_vulnerabilities, pre_rules, post_rules)
    exploit_ability_dict = {"precond": pre_conditions, "postcond": post_conditions}
    
    return exploit_ability_dict


def generate_attack_graph(attack_vector_path, pre_rules, post_rules, topology, vulnerabilities, example_folder):
    """Main pipeline for the attack graph generation algorithm."""
    
    print("Start with attack graph generation...")
    
    # Read the attack vector files.
    attack_vector_files = reader.read_attack_vector_files(attack_vector_path)
    
    time_start = time.time()
    
    # Read the service to image mapping.
    services = topology_parser.get_services(example_folder)
    mapping_names = topology_parser.get_mapping_service_to_image_names(services, example_folder)
    
    # Merging the attack vector files and creating an attack vector dictionary.
    attack_vector_dict = get_attack_vector(attack_vector_files)
    
    # Getting the potentially exploitable vulnerabilities for each container.
    exploitable_vulnerabilities = {}
    for container in topology.keys():
        if container != "outside":
            # Reading the vulnerability
            exploitable_vulnerabilities[container] = get_container_exploitable_vulnerabilities(vulnerabilities
                                                                                               [mapping_names
                                                                                                [container]],
                                                                                               container,
                                                                                               attack_vector_dict,
                                                                                               pre_rules,
                                                                                               post_rules)
    
    duration_vulnerabilities_preprocessing = time.time() - time_start
    print("Vulnerabilities preprocessing finished. Time elapsed: " +
          str(duration_vulnerabilities_preprocessing) +
          " seconds.\n")
    
    # Breadth first search algorithm for generation of attack paths.
    print("Breadth-first search started.")
    nodes, edges, duration_bdf = breadth_first_search(topology, exploitable_vulnerabilities)
    
    print("Breadth-first search finished. Time elapsed: " + str(duration_bdf) + " seconds.\n")
    
    # Returns a graph with nodes and edges.
    return nodes, edges, duration_bdf, duration_vulnerabilities_preprocessing


def print_graph_properties(label_edges, nodes, edges):
    """This functions prints graph properties."""
    
    print("\n**********Attack Graph properties**********")
    
    time_start = time.time()
    
    # Create the graph
    graph = networkx.DiGraph()
    
    for node in nodes:
        graph.add_node(node)
    for edge_name in edges.keys():
        terminal_points = edge_name.split("|")
        
        edge_vulnerabilities = edges[edge_name]
        
        if label_edges == "single":
            for _ in edge_vulnerabilities:
                graph.add_edge(terminal_points[0], terminal_points[1], contstraint='false')
        
        elif label_edges == "multiple":
            graph.add_edge(terminal_points[0], terminal_points[1], contstraint='false')
    
    # Calculate the attack graph properties
    
    # Number of nodes
    no_nodes = graph.number_of_nodes()
    print("The number of nodes in the graph is " + str(no_nodes) + "\n")
    
    # Number of edges
    no_edges = graph.number_of_edges()
    print("The number of edges in the graph is " + str(no_edges) + "\n")
    
    # Degree centrality
    degree_centrality = networkx.degree_centrality(graph)
    print("The degree centrality of the graph is: ")
    for item in degree_centrality.keys():
        print(str(item) + " " + str(degree_centrality[item]))
    
    # Average degree centrality
    avg_degree_centrality = 0
    for node in degree_centrality:
        avg_degree_centrality = avg_degree_centrality + degree_centrality[node]
    if no_nodes != 0:
        avg_degree_centrality = avg_degree_centrality / no_nodes
    print("The average degree centrality of the graph is: " + str(avg_degree_centrality) + "\n")
    
    # In-degree and average in-degree
    in_degree = graph.in_degree
    print("The in-degree is:")
    avg_in_degree = get_avg_degree(in_degree, no_nodes)
    print("The average in-degree is " + str(avg_in_degree) + "\n")
    
    out_degree = graph.out_degree
    print("The out-degree is:")
    avg_out_degree = get_avg_degree(out_degree, no_nodes)
    print("The average out-degree is " + str(avg_out_degree) + "\n")
    
    if no_nodes != 0:
        print("Is the graph strongly connected? " + str(networkx.is_strongly_connected(graph)) + "\n")
    
    duration_graph_properties = time.time() - time_start
    print("Time elapsed: " + str(duration_graph_properties) + " seconds.\n")
    
    return duration_graph_properties


def get_avg_degree(degree, no_nodes):
    if type(degree) == int:
        print(degree)
    else:
        # noinspection PyTypeChecker
        for item in degree:
            print(item)
    
    avg_out_degree = 0
    
    if type(degree) == int:
        avg_out_degree = degree
    else:
        # noinspection PyTypeChecker
        for node in degree:
            avg_out_degree = avg_out_degree + node[1]
        if no_nodes != 0:
            avg_out_degree = avg_out_degree / no_nodes
    
    return avg_out_degree
