git pull
echo "Restarting Web Server"
systemctl restart pentavision-web
echo "Restarting Video Worker"
systemctl restart pentavision-video-worker
echo "All Done Have a nice day"

