make:
	openssl x509 -inform der -in CA.cer -out CA.pem
	openssl pkcs12 -in Cliente.p12 -passin pass:1234 -passout pass:1234 -out Cliente1
	openssl pkcs12 -in Servidor.p12 -passin pass:1234 -passout pass:1234 -out Servidor
	openssl verify -CAfile CA.pem Cliente1 Servidor

python:
	python3 openssl.py

clean:
	rm Cliente1 Servidor CA.pem