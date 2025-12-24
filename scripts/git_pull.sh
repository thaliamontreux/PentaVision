#!/bin/bash
set -e

cd /opt/pentavision/opt

git fetch origin

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse @{u})

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "Updates detected, pulling..."
    git pull 
    echo "Updated! Running POST UPDATE command..."
    systemctl restart pentavision-logserver
    systemctl restart pentavision-video-worker
    systemctl restart pentavision-rtmpsvc
    systemctl restart pentavision-blocklist
    systemctl restart pentavision-access-control
    echo "Thank you for your cooperation have a nice day..." 
else
    echo "No updates."
fi


