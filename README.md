# SemilleroInvestigacion_SeguridadSSL

This tool is a meta-framework developed by some students as a project for the *"SeguridadSSL"* research seed of the *"Universidad de Caldas"*.


Installation
------------

Download the [repository](https://gitlab.com/ShebisX/SemilleroInvestigacion_SeguridadSSL.git), and execute the installation script with the next command:

```bash
$ python setup.py install
```

> Ensure to have [Python](http://www.python.org/download/) 2.7.x installed.

Also, you can install it as a docker container by building the image from the Dockerfile, to do so just run:

```bash
$ docker build .
```

> Ensure to have [Docker](https://www.docker.com/) [installed](https://docs.docker.com/engine/installation/)

Usage
-----

After the installation a script will be added to your system. Run the next command to execute it:

```bash
$ semillero_seguridadssl
```

To use the nmap commands is required to have [Nmap](https://nmap.org/) installed in the same machine.

> If you use it as docker container, as previously stated, you only need to run the container and skip the previous indications.

To use the [Metasploit][metasploit] and [OpenVAS][openvas] modules you need to start the demons and services wheteher is in a local machine or a remote machine.

You can use a [Docker image](https://store.docker.com/) of [Metasploit][metasploit] or [OpenVAS][openvas] that you feel comfortable with to use.

[metasploit]: https://metasploit.help.rapid7.com/docs 'Metasploit'
[openvas]: http://openvas.org/ 'OpenVAS'

**Metasploit:**

```bash
$ msfrpcd -U <username> -P <password> -a <IP address> 
```

> Use `msfrpcd -h` to see other options.

**OpenVAS:**

```bash
$ openvas-start
```

> You can check for errors using `openvas-check-setup` in case the services don't work well.
