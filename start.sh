#!/bin/sh

echo "Starting kippo in background..."
twistd -y kippo.tac -l log/kippo.log --pidfile kippo.pid
