git pull
echo "Restarting Web Server"
systemctl restart pentavision-web
echo "Restarting Blocklist Server"
systemctl restart pentavision-blocklist
echo "Restarting Log Server"
systemctl restart pentavision-logserver
sleep 5
echo "Restarting Video Worker"
systemctl restart pentavision-video-worker
sleep 10
systemctl status pentavision-web
systemctl status pentavision-blocklist
systemctl status pentavision-logserver
systemctl status pentavision-video-worker
