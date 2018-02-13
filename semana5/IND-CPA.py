from Crypto.Cipher import Salsa20
import string
import random
import os

texto1 = ""
texto2 = ""
opcao = "20"

#Definir as variáveis para as estatisticas do jogo
tentativas = 0
certas = 0

#Definir a função que encripta o texto
def encripta_texto(msg):
	global nonce, key
	cifra = Salsa20.new(key=key, nonce=nonce)
	mensagem = cifra.encrypt(msg.encode("utf-8"))
	print("Texto encriptado:")
	print(mensagem)

#Definir a função de advinhar o texto
def advinha_texto():
	global texto1, texto2, opcao, certas
	print("0 : " + texto1)
	print("1 : " + texto2)
	res = input("Qual o texto encriptado? [0/1]")
	if(texto_escolhido == int(res)):
		resposta = input("Acertaste. Desejas jogar novamente? [Sim/Nao]")
		certas+=1
	else:
		resposta = input("Erraste. Desejas jogar novamente? [Sim/Nao]")
	if(resposta == "Nao"):
		opcao="0"


while(int(opcao)!=0):
	print("A iniciar um novo Jogo")

	tentativas+=1
	
	#Introduzir o tamanho dos 2 textos
	#Ainda não varifica se o input é realmente um número
	tamanho = input("Introduza o tamanho do texto a encriptar: ")

	#Introduzir os textos com o tamanho especificado no input, guardado em "tamanho"
	#Verifica se os textos introduzidos são do tamanho correto
	ciclo = True
	while(ciclo):
		texto1 = input("Introduza o primeiro texto com tamanho " + tamanho + ":")
		if(len(texto1) == int(tamanho)):
			ciclo = False
		else:
			print("Tamanho inválido.")

	ciclo = True
	while(ciclo):
		texto2 = input("Introduza o segundo texto com tamanho " + tamanho + ":")
		if(len(texto2) == int(tamanho)):
			ciclo = False
		else:
			print("Tamanho inválido.")

	#Criação de uma password
	key = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(32)).encode("utf-8")

	#Criação do nonce para a utilização na encriptação com o tamanho 8 
	nonce = ''.join([str(random.randint(0, 9)) for i in range(8)]).encode("utf-8")

	#Escolher o texto a encriptar, o "b" apresentado na sintaxe do guião, guardado em "texto_escolhido"
	texto_escolhido = random.randint(0,1)

	if(texto_escolhido == 0):
		encripta_texto(texto1)
	else:
		encripta_texto(texto2)

	#Opções do adversário
	while(int(opcao)!=1 and int(opcao)!=0):
		print("===========================")
		print("Objetivo: Advinhar qual o texto que foi encriptado.")
		print("1 -> Advinhar qual o texto encriptado.")
		print("2 -> Encriptar um texto.")
		print("3 -> Imprimir o texto encriptado.")

		opcao = input("Escreva o número relativo à operação que pretende realizar:")

		try:
			int(opcao)
			if(int(opcao) <1 or int(opcao)>3):
				print("Opção Inválida.")

			if(int(opcao)==1):
				advinha_texto()
			else: 
				if(int(opcao)==2):
					texto = input("Introduza o texto de tamanho " + tamanho + " a encriptar:")
					if(texto != texto1 and texto != texto2):
						encripta_texto(texto)
					else:
						print("Não colocar textos iguais aos textos teste")
				else: 
					if(int(opcao)==3):
						if(texto_escolhido == 0):
							encripta_texto(texto1)
						else:
							encripta_texto(texto2)
		except ValueError:
   			print("Escreva a opção a utilizar")

print("Segurança estabelecida = " + str(2*((certas/tentativas)-0.5)))
