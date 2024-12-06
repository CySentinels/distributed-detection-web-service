# Distributed server architecture

## Install nginx
```bash
sudo apt update
sudo apt install nginx
```

## Configure flask app instances
```bash
gunicorn -w 4 -b 127.0.0.1:5000 app:app &
gunicorn -w 4 -b 127.0.0.1:5001 app:app &
gunicorn -w 4 -b 127.0.0.1:5002 app:app &
```

## Configure nginx
Edit the nginx config file: `/etc/nginx/sites-available/default`
```
upstream prediction_system {
    server 127.0.0.1:5000;
    server 127.0.0.1:5001;
    server 127.0.0.1:5002;
}

server {
    listen 80;

    location / {
        proxy_pass http://prediction_system;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /health {
        proxy_pass http://prediction_system/health;
        proxy_set_header Host $host;
    }
}
```

## Restart nginx
```bash
sudo systemctl restart nginx
```

## Testing the Load Balancer
1. Access the /predict endpoint via the load balancer:
```
curl -X GET "http://<your_server_ip>/predict?url=https://example.com"
```
2. Nginx will distribute requests among the Flask instances on ports 5000, 5001, and 5002.
3. Monitor Nginx logs for traffic distribution:
```bash
sudo tail -f /var/log/nginx/access.log
```
