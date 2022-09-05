# mAGG: a managed Attack Graph Generator

## Installing

### System Requirements

The following dependencies are needed:

* bash
* Python >= 3.10
* Docker Desktop (Engine >= 19.03, Compose >= 1.27)
* go

You may install them with 
```
./install_dependencies.bash
```
Note that this script is recommended to be running on following systems:

* macOS Monterey
* Manjaro Linux
* Ubuntu 22.04 LTS
* Kali 2022.2

Other versions of the above OS, e.g. `Ubuntu 20.04 LTS`, `macOS Big Sur`, 
[install_dependencies.bash](install_dependencies.bash) should also work. 
Also, the script may work on all `Arch-Based Linux` distros and `Debian Linux`.

### Python modules
The needed python modules are listed in [requirements.txt](requirements.txt). You can simply install them by 
```
pip install -r requirements.txt
```

Note that if you use [install_dependencies.bash](install_dependencies.bash) for system requirements,
it will create a virtualenv in directory venv with the name of your OS type. 
If your python is not configured to use venv,
then the modules will be installed globally.

For example, on Debian-based Linuxes like Ubuntu 22.04 or Kali 2022.2, you need to run
```
sudo apt install python3.10-venv
```
to have venv enabled. Please change ```python3.10``` to your python major version.


## Running

The general usage of the script is:

```
$ ./main.py {CONFIG_DIR}
```

The above command starts the [main.py](main.py) script and generates an attack graph for the system in the directory
`{CONFIG_DIR}`. 
It performs the attack graph analysis. Note that a `docker-compose.yaml` is needed in the directory.

Examples are
```
$ ./main.py ./examples/1_example
$ ./main.py ./examples/atsea
```

* Please note that on the first try, `Clair` populates the database, so that is why the attack graph will be empty. 
* Furthermore, building the images in the vulnerability-parser for the first time takes longer. The code is tested
on a macOS and on the virtual machines of above-mentioned operating systems hosted on it.

## Customizing the attack graph generation

The config file is the main point where the attack graphs can be customized. 
The attack graph generation can be conducted in either online or offline mode. 
Online mode uses Clair for vulnerabilities detection and takes more time. 
Offline mode uses already created vulnerability files (by Clair) and performs the attack graph analysis. 
Therefore, the offline mode does not require an internet connection. Because the edges can have many vulnerabilities, 
there is an option if we want to display the attack graph with separate edges with different vulnerabilities 
or combine all of them in one edge. Another option is to display only one vulnerability per edge in the attack graph. 
Finally, the user has to possibility to modify the pre- and postcondition rules 
from which the attack graphs are created. For additional details on how to use the config file, please refer to 
the comments in the config.yml file.

## License and Acknowledgments

Copyright 2022 张瀚文

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This project uses the tools cloned from 
[tum-i4/attack-graph-generator](https://github.com/tum-i4/attack-graph-generator)
by ibrahim *et al.* for [CVE](https://cve.org) and [NVD](https://nvd.nist.gov) data reading and parsings, 
sharing same config file settings, For details, [Clair](https://github.com/quay/clair) version 2.1.8,
and [claircrl](https://github.com/jgsqware/clairctl) are used for vulnerability exploiting.

As the names of some python files and functions still remain the same, 
their implementations, algorithms and return variables are  based on our proposed methods
for topology parsings and attack graph generations.

A git branch named 'old' contains the modified original works as benchmark:

> Ibrahim, Amjad, Stevica Bozhinoski, and Alexander Pretschner.
> "Attack graph generation for microservice architecture."
> Proceedings of the 34th ACM/SIGAPP Symposium on Applied Computing. ACM, 2019.
