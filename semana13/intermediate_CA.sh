#Criar as diretorias que irão guardar os componentes da CA
cd ./root/ca/
mkdir intermediate
cd ./intermediate
mkdir certs crl csr newcerts private
chmod 700 private
#Index e Serial atuam como bases de dados dos certificados assinados
touch index.txt
echo 1000 > serial
#crlnumber é usado como base de dados para as 
#certificate revocation lista
echo 1000 > crlnumber
#Copiar o ficheiro de configuração da CA Intermédia
cp ../../../intermediate_openssl.cnf .
mv intermediate_openssl.cnf openssl.cnf

echo "------------------------"
#Gera a chave privada para o certificado
openssl genrsa -aes256 \
      	-out private/intermediate.key.pem 4096
#Apenas quem criou poderá aceder
chmod 400 private/intermediate.key.pem

echo "------------------------"
#Criar um certificate signing request (CSR) para a CA Root
#Assinar, tornando esta uma CA confiável
echo "O Common Name terá de ser diferente do Common Name da Root CA"
openssl req -config openssl.cnf -new -sha256 \
      	-key private/intermediate.key.pem \
      	-out csr/intermediate.csr.pem

echo "------------------------"
#Criar o certificado da CA Intermédia, assinado pela CA Root
openssl ca -config ../openssl.cnf -extensions v3_intermediate_ca \
      	-days 3650 -notext -md sha256 \
      	-in csr/intermediate.csr.pem \
      	-out certs/intermediate.cert.pem
#Apenas é permitida a leitura do ficheiro
chmod 444 certs/intermediate.cert.pem

echo "------------------------"
#Verificar o certificado intermédio
openssl x509 -noout -text \
      	-in certs/intermediate.cert.pem
openssl verify -CAfile ../certs/ca.cert.pem \
      	certs/intermediate.cert.pem
#Criar a chain file certificate, para aquando a verficação
#de um certificado assinado pela CA intermédia, terá também
#de verificar a CA Root.
cat certs/intermediate.cert.pem \
    ../certs/ca.cert.pem > certs/ca-chain.cert.pem
#Apenas é permitida a leitura do ficheiro
chmod 444 certs/ca-chain.cert.pem