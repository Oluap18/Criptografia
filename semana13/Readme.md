#Para a realização deste projeto, foi utilizadas as seguintes fontes:

#Criação da Root_CA, Intermediate_CA e Certificados do server e cliente.
https://jamielinux.com/docs/openssl-certificate-authority/index-full.html

#Criação do pkcs12
https://www.openssl.org/docs/manmaster/man1/openssl-pkcs12.html

#Para a criação dos certificados para uso do Server e Cliente, é necessário criar uma Autoridade de Certificação Root, auto-assinada, criando de seguida uma Autoridade de Certificação intermédia, assinada pela CA Root, para proteger ao máximo a CA Root.

#De seguida iremos demonstrar os passos necessários para a criação destes componentes sem usar a Makefile:

#1º Mudar o valor da variável dir nos ficheiros root_openssl.cnf e intermediate_openssl.cnf
#para o caminho absoluto onde serão criados os componentes, sendo estes: 
#{diretoria_currente}/root/ca e {diretoria_currente}/root/ca/intermediate respetivamente

#2º Criação da Autoridade de Certificação Root:
./root_ca.sh
#Execução do script "root_CA.sh" onde tem explicado os passos a seguir para a criação a Autoridade de Certificação Root.

#3º Criação da Autoridade de Certificação Intermédia Assinada pela CA Root:
./intermediate_CA.sh
#Execução do script "intermediate_CA.sh" onde tem explicado os passos a seguir para a criação a Autoridade de Certificação intermédia.
#Deverá ser executado na diretoria root/ca, criado pelo root_ca.sh

#4º Criação de pkcs12 dos clientes e do servidor, assinados pela CA intermédia.
./certificate.sh {Certificate Name}
#Execução do script "certificate.sh", com o nome do pkcs12 como argumento, onde tem explicado os passos a seguir para a criação da keystore.

#Iremos agora demonstrar os passos necessários para a criação destes componentes usando a Makefile:
#1º Mudar o valor da variável dir nos ficheiros root_openssl.cnf e intermediate_openssl.cnf
#para o caminho absoluto onde serão criados os componentes, sendo estes: 
#{diretoria_currente}/root/ca e {diretoria_currente}/root/ca/intermediate respetivamente

#2º Utilizar a função build da Makefile, que cria o CA Root e o CA intermédio
make build

#3º Criação de pkcs12 dos clientes e do servidor, assinados pela CA intermédia.
./certificate.sh {Certificate Name}
#Execução do script "certificate.sh", com o nome do pkcs12 como argumento, onde tem explicado os passos a seguir para a criação da keystore.

#A Makefile também suporta as funções root_c e intermediate_c, que limpa as pastas ./root e ./root/ca/intermediate respetivamente.

#Iremos deixar agora umas notas sobre a aplicação relativa aos Clientes e ao Servidor, assim como a implementação da cifra.

#A aplicação que implementa o Servidor (Servidor.py) implementa o protocolo Station_to_Station fazendo uso de certificados X509 e de keystores PKCS12, implementando assim:

#1. Servidor → Cliente : gx
#2. Cliente → Servidor : gy, SigB(gx, gy), CertB
#3. Servidor → Cliente : SigA(gx, gy), CertA
#4. Servidor, Cliente : K = g(x*y)

#Assim, para evitar ataques de man-in-the-middle, é enviado uma assinatura dos utilizadores, assim como o certificado (que será verificado a ver se é assinado por uma CA válida) que contêm a chave publica correspondente correspondente à assinatura enviada.
#Caso sejam executados os passos acima demonstrados para criar as CAs, os certificados irão estar nas posições corretas para a aplicação os verificar.
#Depois de serem verificadas as entidades, caso ambos se verifiquem ser quem alegam que são, as mensagens enviadas serão cifradas com K.