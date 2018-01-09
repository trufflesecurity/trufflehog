docker build -t trufflehog .
docker run -d --name trufflehog_instance -p 8080:8080 -i -t trufflehog