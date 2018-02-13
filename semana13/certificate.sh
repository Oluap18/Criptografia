#Script suportado para criar certificados para o server ou para o clientes
cd ./root/ca

echo "------------------------"
#Gerar a chave privada do certificado
openssl genrsa -aes256 \
      	-out intermediate/private/$1.key.pem 2048
#Só o criador do certificado poderá aceder à chave
chmod 400 intermediate/private/$1.key.pem

echo "------------------------"
echo "Nos campos Organizational Unit Name e Common Name, especifique que certificado está a criar"
#Criar um certificate signing request (CSR) para a CA intermédia
#Assinar, tornando este um certificado confiável
openssl req -config ../../intermediate_openssl.cnf \
      	-key intermediate/private/$1.key.pem \
      	-new -sha256 -out intermediate/csr/$1.csr.pem

echo "------------------------"
#Assinar o CSR com a CA intermédia. Se for um certificado
#Para um servidor, deverá usar a extensão server_cert
#Noutro caso, deverá usar o usr_cert
if [ "$1" == "Servidor" ] || [ "$1" == "servidor" ]
then
	openssl ca -config intermediate/openssl.cnf \
      		-extensions server_cert -days 375 -notext -md sha256 \
      		-in intermediate/csr/$1.csr.pem \
     	 	  -out intermediate/certs/$1.cert.pem
else
	openssl ca -config intermediate/openssl.cnf \
      		-extensions usr_cert -days 375 -notext -md sha256 \
      		-in intermediate/csr/$1.csr.pem \
     	 	  -out intermediate/certs/$1.cert.pem
fi
#Apenas se poderá ler o ficheiro
chmod 444 intermediate/certs/$1.cert.pem

echo "------------------------"
openssl x509 -noout -text \
      	-in intermediate/certs/$1.cert.pem
#Proceder à verificação do certificado
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
      	intermediate/certs/$1.cert.pem

echo "------------------------"
#Criação da pkcs12
openssl pkcs12 -export \
		    -inkey intermediate/private/$1.key.pem \
		    -in intermediate/certs/$1.cert.pem \
		    -out $1.p12
cp $1.p12 ../../