# mAGG: a multi-layer attack graph generator

## Installing

### System Requirements

The following dependencies are needed:

* python3
* docker
* docker-compose
* go
* graphviz
* clairctl

You may install them with 
```
./install_dependencies.bash
```
Note that this script is designed to be running on following systems:

* macOS Monterey
* Manjaro Rolling (in 2022.5)
* Ubuntu 22.04 LTS
* Kali Rolling 2022.2.4

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
$ ./main.py ./examples/example
```

The above command starts the [main.py](main.py) script and generates an attack graph for the system ./examples/atsea. 
It performs the attack graph analysis.

Other examples are
```
$ ./main.py ./examples/1_example
$ ./main.py ./examples/atsea
```

* Please note that on the first try, Clair populates the database, so that is why the attack graph will be empty. 
* Furthermore, building the images in the vulnerability-parser for the first time takes longer. The code is tested
* on a virtual machine running on the above-mentioned operating system.

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

## Acknowledgments

This project is modified from the tool [attack-graph-generator](https://github.com/tum-i4/attack-graph-generator)
by ibrahim *et al.*

### Original authors
* Stevica Bozhinoski stevica.bozhinoski@tum.de
* Amjad Ibrahim, M.Sc. amjad.ibrahim@tum.de

please also site this academic work: 

> Ibrahim, Amjad, Stevica Bozhinoski, and Alexander Pretschner.
>  "Attack graph generation for microservice architecture."
> Proceedings of the 34th ACM/SIGAPP Symposium on Applied Computing. ACM, 2019.
> 
> @inproceedings{ibrahim2019attack,
  title={Attack graph generation for microservice architecture},
  author={Ibrahim, Amjad and Bozhinoski, Stevica and Pretschner, Alexander},
  booktitle={Proceedings of the 34th ACM/SIGAPP Symposium on Applied Computing},
  pages={1235--1242},
  year={2019},
  organization={ACM}
}

We would like to thank the teams of [Clair](https://github.com/coreos/clair) 
and [Clairctl](https://github.com/jgsqware/clairctl) for their vulnerability generator,
which is an integral part of our system.
Additional thanks to the contributors of all of third-party tools used in this project.

