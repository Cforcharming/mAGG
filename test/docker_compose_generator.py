#!/usr/bin/env python

"""Module for generating big docker compose files."""

import os
import shutil

import yaml


def generate_compose_file(dir):
    """Function that generates the docker-compose.yml with number of samba containers."""
    
    times_python = int(dir.split('/')[3].split('-')[0])
    
    if not os.path.exists(dir):
        os.makedirs(dir)
    
    data = {"version": "3.8",
            "networks": {"frontend": {"driver": "bridge"},
                         "backend": {"driver": "bridge"}},
            "services": {"tc": {"image": "tomcat",
                                "networks": ["frontend"],
                                "ports": ["80"]}}}
    
    for i in range(1, times_python + 1):
        name_container = "py" + str(i)
        dict_container = {"image": "python",
                          "networks": ["frontend"]}
        data["services"][name_container] = dict_container
    
    shutil.copy(os.path.join(os.getcwd(), '../examples/example/tomcat-vulnerabilities.json'), dir)
    shutil.copy(os.path.join(os.getcwd(), '../examples/example/python-vulnerabilities.json'), dir)
    
    with open(os.path.join(dir, 'docker-compose.yml'), 'w') as outfile:
        yaml.dump(data, outfile, default_flow_style=False)


generate_compose_file('../examples/full-conn/1-example/')
generate_compose_file('../examples/full-conn/5-example/')
generate_compose_file('../examples/full-conn/10-example/')
generate_compose_file('../examples/full-conn/50-example/')
generate_compose_file('../examples/full-conn/100-example/')
generate_compose_file('../examples/full-conn/150-example/')
generate_compose_file('../examples/full-conn/200-example/')
generate_compose_file('../examples/full-conn/250-example/')
generate_compose_file('../examples/full-conn/300-example/')
generate_compose_file('../examples/full-conn/350-example/')
generate_compose_file('../examples/full-conn/400-example/')
generate_compose_file('../examples/full-conn/450-example/')
generate_compose_file('../examples/full-conn/500-example/')
generate_compose_file('../examples/full-conn/550-example/')
generate_compose_file('../examples/full-conn/600-example/')
generate_compose_file('../examples/full-conn/650-example/')
generate_compose_file('../examples/full-conn/700-example/')
generate_compose_file('../examples/full-conn/750-example/')
generate_compose_file('../examples/full-conn/800-example/')
generate_compose_file('../examples/full-conn/850-example/')
generate_compose_file('../examples/full-conn/900-example/')
generate_compose_file('../examples/full-conn/950-example/')
generate_compose_file('../examples/full-conn/1000-example/')
