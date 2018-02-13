#Criar as diretorias que irão guardar os componentes da CA
mkdir ./root
cd ./root
mkdir ./ca
cd ./ca
mkdir certs crl newcerts private
chmod 700 private
#Index e Serial atuam como bases de dados dos certificados assinados
touch index.txt
echo 1000 > serial

#Copiar o ficheiro de configuração da CA Root
cp ../../root_openssl.cnf .
mv root_openssl.cnf openssl.cnf

echo "------------------------"
#Gerar a chave privada do certificado da CA Root
openssl genrsa -aes256 -out private/ca.key.pem 4096
#Só o criador do certificado poderá aceder à chave
chmod 400 private/ca.key.pem

echo "------------------------"
#Criar o certificado root ca.cert.pem com a chave ca.key.pem usando 
#as configurações do ficheiro openssl.cnf
openssl req -config openssl.cnf \
      	-key private/ca.key.pem \
      	-new -x509 -days 7300 -sha256 -extensions v3_ca \
      	-out certs/ca.cert.pem
#Apenas é permitida a leitura do ficheiro
chmod 444 certs/ca.cert.pem

echo "------------------------"
#Verificar o Certificado root
openssl x509 -noout -text -in certs/ca.cert.pem
cp ../../intermediate_CA.sh .