# Actions

.PHONY: certs clean clean-certs

certs: ca.key ca.crt spb-serpro.key spb-serpro.crt spb-caixa.key spb-caixa.crt part-a.key part-a.crt part-b.key part-b.crt

clean: clean-certs

clean-certs:
	rm -f *.key *.crt *.csr


# Files

%.key:
	openssl genrsa -out $@ 2048

ca.crt: ca.key
	openssl req -x509 -new -key $< -out $@ -subj '/CN=ICP-Brasil Fake' -days 365

spb-%.csr: spb-%.key
	openssl req -new -key $< -out $@ -subj '/CN=AC $* Fake'

spb-%.crt: spb-%.csr ca.crt ca.key
	openssl x509 -req -CA ca.crt -CAkey ca.key -in $< -out $@ -days 365

%.csr: %.key
	openssl req -new -key $< -out $@ -subj '/CN=$* Fake'

part-a.crt: part-a.csr spb-serpro.crt spb-serpro.key
	openssl x509 -req -CA spb-serpro.crt -CAkey spb-serpro.key -in $< -out $@ -days 365 -set_serial $(shell printf '%d' 0x$(shell openssl rand -hex 4))

part-b.crt: part-b.csr spb-caixa.crt spb-caixa.key
	openssl x509 -req -CA spb-caixa.crt -CAkey spb-caixa.key -in $< -out $@ -days 365 -set_serial $(shell printf '%d' 0x$(shell openssl rand -hex 4))
