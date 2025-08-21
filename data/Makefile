# Actions

.PHONY: certs clean clean-certs

certs: ca.key ca.crt part-a.key part-a.crt part-b.key part-b.crt

clean: clean-certs

clean-certs:
	rm -f *.key *.crt *.csr


# Files

ca.key:
	openssl genrsa -out $@ 2048

ca.crt: ca.key
	openssl req -x509 -new -key $< -out $@ -subj '/CN=Fake CA' -days 365

%.key:
	openssl genrsa -out $@ 2048

%.csr: %.key
	openssl req -new -key $< -out $@ -subj '/CN=$*'

%.crt: %.csr ca.crt ca.key
	openssl x509 -req -CA ca.crt -CAkey ca.key -in $< -out $@ -copy_extensions copy -days 365
