#!/usr/bin/env python

"""Module for generating big docker compose files."""

import os
import shutil

import yaml


def generate_compose_file(example_dir):
    """Function that generates the docker-compose.yml with number of samba containers."""
    
    times_python = int(example_dir.split('/')[2].split('-')[0])
    
    if not os.path.exists(example_dir):
        os.makedirs(example_dir)
    
    data = {"version": "3.8",
            "networks": {"frontend": {}},
            "services": {"tc": {"image": "tomcat",
                                "networks": ["frontend"],
                                "ports": ["80"]}}}
    
    for i in range(1, times_python + 1):
        name_container = "py" + str(i)
        dict_container = {"image": "python",
                          "networks": ["frontend"]}
        data["services"][name_container] = dict_container
    
    shutil.copy(os.path.join(os.getcwd(), 'examples/example/tomcat-vulnerabilities.json'), example_dir)
    shutil.copy(os.path.join(os.getcwd(), 'examples/example/python-vulnerabilities.json'), example_dir)
    
    with open(os.path.join(example_dir, 'docker-compose.yml'), 'w') as outfile:
        yaml.dump(data, outfile, default_flow_style=False)


if __name__ == '__main__':
    x = list(range(50, 1001, 50))
    x.append([1, 5, 10])
    for j in x:
        generate_compose_file('examples/full-conn/' + str(j) + '-example/')
