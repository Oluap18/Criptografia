# Guiões das Sessões Laboratoriais realizado em conjunto com [João Miguel](http://jrsmiguel.me/)

---
## FINALIZAÇÃO 

### Arrumação do repositório

Uma vez concluída a realização dos guiões das sessões laboratoriais, sugere-se que procedam à **arrumação** do repositório seguindo a seguinte estrutura:

```
+-- Readme.md: ficheiro se apresenta o conteúdo do repositório, dando nota dos aspectos que
|              entenderem relevante salientar (e.g. dar nota de algum guião que tenha ficado
|              por realizar ou incompleto; um ou outro guião que tenha sido realizado apenas
|              por um dos membros do grupo; etc.)
+-- Semana3
|        +-- Readme.md: notas sobre a realização do guião da semana 3 (justificação das opções
|        |              tomadas; instruções de uso; dificuldades encontradas; etc.)
|        +-- ...
|
+-- Semana4
|        +-- ...
...
|
+-- Semana11
|        +-- ...
|
+-- AppCifra
|        +-- Readme.md: notas sobre a aplicação de cifra de ficheiro final (deverá corresponder
|        |              essencialmente a uma versão eventualmente melhorada do guião da semana 4)
|        +-- ...
|
+-- CliServ
         +-- Readme.md: notas sobre a aplicação Cliente/Servidor final (deverá corresponder
         |              essencialmente a uma versão eventualmente melhorada do guião da semana 11)
         +-- ...
```

Sugere-se ainda que mantenham nas directorias `SemanaX` os trabalhos realizados efectivamente nas semanas
respectivas, reservando a introdução de melhorias e/ou conclusão de algum ponto que tenha ficado por realizar
para os projectos finais `AppCifra` e `CliServ` (note que esses projectos acabam por agregar a generalidade dos
guiões pedidos).

---
## Semana 13

### Geração de Certificados para a aplicação

Para concluir a aplicação Cliente/Servidor pretende-se gerar os certificados requeridos. Para tal deve
usar qualquer das várias sugestões de software livre disponívies para o efeito - uma escolha óbvia é naturalmente
o `openssl` a que já recorremos antes, mas preferindo podem utilizar uma solução de mais alto nível, como a [EJBCA](https://www.ejbca.org).

Na realização do guião desta semana, deve adicionar ao reposotório um ficheiro `MarkDown` (e.g. `Readme.md`) contendo:
 1. as fontes utilizadas (tutoriais utilizados ou outros recursos)
 1. os passos seguidos para a criação dos certificados, _keystores_, etc.
 1. e, se for o caso, instruções para replicar o processo.
 
Pode ainda adicionar _scripts_ e outros ficheiros de suporte utilizados.

Alguns apontadores:
 * http://pki-tutorial.readthedocs.io/en/latest/expert/
 * https://jamielinux.com/docs/openssl-certificate-authority/index-full.html
 * https://roll.urown.net/ca/ca_intermed_setup.html

---
## Semana 12

### Finalização do protocolo StS usando certificados

No guião desta semana vamos concluir a implementação do protocolo _Station_to_Station_ fazendo uso de certificados X509. Para tal vamos incorporar a funcionalidade explorada no último guião (validação dos certificados).

Concretamente, o protocolo a implementar irá ser então:
1. Alice → Bob : g<sup>x</sup>
1. Bob → Alice : g<sup>y</sup>, Sig<sub>B</sub>(g<sup>x</sup>, g<sup>y</sup>), Cert<sub>B</sub>
1. Alice → Bob :  Sig<sub>A</sub>(g<sup>x</sup>, g<sup>y</sup>), Cert<sub>A</sub>
1. Alice, Bob : K = g<sup>(x*y)</sup>

Note que os pares de chave a utilizar neste guião são os fornecidas nas _keystores_ PKCS12 fornecidos no guião da semana 11.

---
## Semana 11

### Manipulação de Certificados X509

O objectivo nesta semana é o de se investigar formas de validar _cadeias de certificados_ em _Python_. A ideia é que, mais tarde, esses certificados serão incorporados na aplicação clente-servidor que temos vindo a implementar - mas neste guião o objectivo é forcar no aspecto da _validação_ desses certificados.

Como ponto de partida, disponibiliza-se:

 1. Uma _keystore_ PKCS12 contendo o Certificado (e respectiva chave privada) para o rervidor: [Servidor.p12](Servidor.p12)
 1. Uma _keystore_ PKCS12 contendo o Certificado (e respectiva chave privada) para o cliente: [Cliente.p12](Cliente.p12) 
 1. O Certificado (em formato DER) da CA utilizada: [CA.cer](CA.cer)

Para aceder ao conteúdo das `Keystores` devem utilizar a password "1234", quer para carregar a `keystore`, quer para aceder à entrada respectiva (o `alias` é `Cliente1` e `Servidor` para as keystores `Cliente.p12` e `Servidor.p12` respectivamente).

Numa primeira fase, utilizaremos ferramentas de domínio público directamente na linha-de-comando. Concretamente, utilizaremos o [openSSL](https://www.openssl.org), e em particular os sub-comandos (ver respectiva documentação):
 - [`x509`](https://www.openssl.org/docs/manmaster/man1/openssl-x509.html);
 - [`pkcs12`](https://www.openssl.org/docs/manmaster/man1/openssl-pkcs12.html);
 - [`verify`](https://www.openssl.org/docs/manmaster/man1/verify.html).

Uma vez ultrapassado esse passo, vamos considerar como transpor esse método de validação para o _Python_, por forma a ser usável na aplicação cliente-servidor. A dificuldade é que as bibliotecas que temos vindo a utilizar não dispõe dessa funcionalidade, pelo que se sugere a instalação/utilização da biblioteca [PyOpenSSL](https://pyopenssl.org/en/stable/index.html).

Referências adicionais:
 - http://www.yothenberg.com/validate-x509-certificate-in-python/
 - http://aviadas.com/blog/2015/06/18/verifying-x509-certificate-chain-of-trust-in-python/
 - https://stackoverflow.com/questions/6345786/python-reading-a-pkcs12-certificate-with-pyopenssl-crypto

---
## Semana 10

### Protocolo *Station-to-Station* simplificado

Pretende-se complementar o programa com o acordo de chaves *Diffie-Hellman* para incluir a funcionalidade
análoga à do protocolo *Station-to-Station*. Recorde que nesse protocolo é adicionado uma troca de assinaturas:

1. Alice → Bob : g<sup>x</sup>
1. Bob → Alice : g<sup>y</sup>, Sig<sub>B</sub>(g<sup>x</sup>, g<sup>y</sup>)
1. Alice → Bob :  Sig<sub>A</sub>(g<sup>x</sup>, g<sup>y</sup>)
1. Alice, Bob : K = g<sup>(x*y)</sup>

De notar que um requisito adicional neste protocolo é a manipulação de pares de chaves assimétricas para realizar as assinaturas digitais (e.g. RSA). Para tal deve produzir um pequeno programa que gere os pares de chaves para cada um dos intervenientes e os guarde em ficheiros que serão lidos pela aplicação Cliente/Servidor.

Sugestão: comece por isolar as "novidades" requeridas pelo guião, nomeadamente:
  1. criação do par de chaves para a assinatura e utilização dos métodos para ''assinar'' e ''verificar''

  1. gravar as chaves públicas/privadas em ficheiro
  
  1. integrar as assinaturas no protocolo _Diffie-Hellman_

---
## Semana 9

### Protocolo *Diffie-Hellman*

Pretende-se implementar o protocolo de acordo de chaves *Diffie-Hellman* fazendo uso da funcionalidade oferecida pela biblioteca `cryptography`. Em concreto, utilizando a classe [`dh`](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/).

Algumas observações:
 * Se pretender, pode fixar os parâmetros do grupo (utilizando, por exemplo, os fornecidos no guião anterior)
 * A documentação da biblioteca não é muito clara na forma como se pode comunicar as chaves públicas DH, tal como requerido pelo protocolo. Na prática, existem duas alternativas:
    * Aceder ao valor (inteiro) da chave pública através da classe `DHPublicNumbers`
    * Utilizar as facilidades de serialização da chave pública oferecidas pela biblioteca (acessível a partir do método `public_bytes` da classe `DHPublicKey`).

---
## Semana 8

### [OPCIONAL] Acordo de chaves _Diffie\_Hellman_

Relembre o protocolo de acordo de chaves _Diffie\_Hellman_:

 1. Alice → Bob : g<sup>x</sup>
 1. Bob → Alice : g<sup>y</sup>
 1. Alice, Bob : K = g<sup>(x*y)</sup>

Onde `g` é um gerador de um grupo cíclico de ordem prima `p`, `x` e `y` são elementos aleatórios do grupo, e `K` é o segredo estabelecido pelo protocolo. Todas as operaçes são realizadas módulo `p`.

Pretende-se implementar esse protocolo de acordo de chaves codificando directamente as operações matemáticas apresentadas. 
Se pretenderem, podem começar por considerar os seguintes parâmetros na definição do grupo:

```
P = 99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583
G = 44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675
```

Obs: uma excelente para referência com informação sobre algoritmos requeridos na codificação das técnicas criptográficas é o [Handbook of Applied Cryptography](http://cacr.uwaterloo.ca/hac/).



---
## Semana 7

### Comunicação entre cliente-servidor (cont.)

Selecção, discussão, refinamento e implementação da solução para gestão das chaves de entre as abordagens dos vários grupos.


---
## Semana 6

### Comunicação entre cliente-servidor

As scripts [Cliente.py](scripts/Cliente.py),
[Servidor.py](scripts/Servidor.py) constituem uma implementação muito
básica de uma aplicação que permite a um número arbitrário de
clientes comunicar com um servidor que escuta num dado port
(e.g. 8888). O servidor atribui um número de ordem a cada cliente, e
simplesmente faz o _dump_ do texto enviado por eese cliente
(prefixando cada linha com o respectivo número de ordem). Quando um
cliente fecha a ligação, o servidor assinala o facto (e.g. imprimindo
[n], onde _n_ é o número do cliente).

Exemplo da execução do servidor (que comunica com 3 clientes):


```bash
$ python3 Servidor.py
1 : daskj djdhs slfghfjs askj
1 : asdkdh fdhss
1 : sjd
2 : iidhs
2 : asdjhf sdga
2 : sadjjd d dhhsj
3 : djsh
1 : sh dh d   d
3 : jdhd kasjdh as
2 : dsaj dasjh
3 : asdj dhdhsjsh
[3]
2 : sjdh
1 : dhgd ss
[1]
2 : djdj
[2]
```

Pretende-se:

 * Modificar as respectivas classes por forma a garantir a
   _confidencialidade_ e _integridade_ nas comunicações
   estabelecidas.
 * Para o efeito, deverá considerar uma cifra por blocos no modo que
   considerar mais apropriado.
 * Realize uma análise crítica do tratamento associado ao armazenamento
   dos segredos requeridos pela sua aplicação (quer da perspectiva da
   segurança, como da usabilidade)

---
## Semana 5

### Animação dos modelos de segurança


Pretende-se animar em _Python_ os "jogos" que servem de base aos modelos de segurança
adoptados na formalização das provas de segurança. Especificamente,
sugere-se ilustrar ataque(s) à confidencialidade das cifras, recorrende à definição de
**IND-CPA** (_indistinguibilidade na presença
de ataques de texto-limpo escolhido_). Recorda-se que o jogo `IND-CPA` é definido
como (apresentado numa sintaxe que pretende facilitar a transposição para a respectiva
codificação em _Python_).

```
IND_CPA(C,A) =
  k = C.keygen()
  enc_oracle = lambda ptxt: C.enc(k,ptxt)
  m[0], m[1] = A.choose(enc_oracle)
  b = random_bit()
  c = C.enc(k,m[b])
  b' = A.guess(enc_oracle, c)
  return b==b'
```

Obs: `m[0]` e `m[1]` devem ser mensagens com um tamanho fixo pré-determinado; assume-se
ainda que o adversário `A` dispõe de "variáveis de instância" que armazena o estado
a preservar entre as duas chamadas.

A segurança é estabelecida quando, para qualquer adversário, a sua **vantagem** definida
como `2 * | Pr[IND_CPA(C,A)=1] - 1/2 |` é negligênciável. Naturalmente que verificar a
segurança de uma cifra concreta `C` estará fora do alcance de uma "animação" do jogo
`IND-CPA`, mas pode servir para ilustrar **ataques** instanciando um adversário que
permita um desvio significativo na probabilidade de sucesso do jogo.

Sugestões:
 * O mecanismo de classes do _Python_ é particularmente útil na parametrização dos jogos;
 * Uma cifra claramente insegura, como a cifra `Identidade` (onde as operações de cifrar
 e decifrar são a função identidade) pode ser útil para ilustrar os conceitos.
 * Alguns exemplos de ataques mencionados nas aulas que podem ser ilustrados: insegurança
 das cifras determinísticas; do mecanismo _encrypt\_and\_mac_; modo ECB de uma cifra por
 blocos.



---
## Semana 4

### Melhoramentos sobre o guião da semana anterior

Do ponto de vista de segurança, o aspecto mais crítico no
guião da semana passada é o tratamento dado aos segredos
criptográficos utilizados. De facto, e para além de se
certificar que se usa um **gerador de números aletórios
seguro** (como o disponibilizado em `Crypto.Random`), é
em geral desaconselhado armazenar segredos criptográficos
em ficheiros sem qualquer protecção.

Existem duas estratégias para evitar gravar esses ficheiros desprotegidos:

 1. Evitar a necessidade de se armazenar a chave. Para isso, considera-se
 um mecanismo seguro que permita gerar um segredo criptográfico a partir
 de uma _password_ ou _passphrase_ (que naturalmente não podem ser utilizadas
 directamente como chaves criptográficas). Para o efeito faz-se uso das
 designadas _Password Based Key Derivation Functions (PBKDF)_.
 2. Armazenar o ficheiro de forma protegida, no que se designa habitualmente por
 *KeyStore*. Na realidade, esta estratégia acaba por partilhar muitos dos requisitos
 da apresentada antes, porque para protegermos
 o ficheiro iremos ter de (internamente) usar uma cifra autenticada, e para isso
 necessitaremos de um novo segredo. Mas, tal como no ponto anterior, esse segredo
 pode ser gerado a partir de uma _password_.
 
Pretende-se assim adicionar à funcionalidade pedida no guião anterior a protecção
dos segredos de acordo com uma das estratégias apresentadas. Quem o desejar, pode
permitir qualquer uma das duas alternativas (e.g. através um argumento opcional que
indique a _KeyStore_ a utilizar - assim se nada for indicado recorre a uma cifra
baseada em _password_).
Adicionalmente, e aproveitando o facto de a biblioteca [cryptography](https://cryptography.io/en/latest/)
dispor de uma API para KDFs bem mais desenvolvida do que a [PyCryptodome](https://www.pycryptodome.org/en/latest/)
utilizada na semana anterior, iremos migrar o desenvolvimento da aplicação desenvolvida para utilizar essa biblioteca. 
---
## Semana 3

### Cifra de Ficheiro

Pretende-se cifrar o conteudo de um ficheiro. Pretende-se que, para
além de garantir a *confidencialidade*, se garanta também a
*integridade* dos dados armazenados nesse ficheiro. Para tal deve
combinar as técnicas que oferecem cada uma dessas funcionalidade - concretamente, as _Cifras_ e _MACs_.

O objectivo é então o de definir uma script _Python_ que permita
cifrar/decifrar um ficheiro utilizando a cifra simétrica RC4.
Sugere-se a utilização de `Salsa20` como cifra, e de `HMAC-Sha256`
como MAC.

Sugestões:

 O enunciado deixa em aberto como gerir a *chave* requerida pela cifra.

  * Numa primeira fase, e para simplificar, pode codificar
   directamente a chave secreta no próprio código da aplicação.
 
  * Deve depois procurar encontrar uma solução "mais definitiva" para
  o problema de gestão da chave. Trata-se de um assunto que iremos
  abordar nas aulas, mas pretende-se que implementem uma solução que
  vos parceça sensata (e.g. gravar a chave de um ficheiro, ou derivar
  a chave de uma _pass phrase_).
