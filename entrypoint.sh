#!/bin/bash
ansible-playbook entrypoint.yml  -c local  --tags run
echo "Sleeping awaiting action!"
/bin/sleep infinity
