from OpenSSL import crypto

def verify_chain_of_trust(cert_pem, trusted_cert_pems):
	#Transformar o pkcs12 em pem
    p12 = crypto.load_pkcs12(open(cert_pem, 'rb').read(), "1234")
    privatekey = p12.get_privatekey()
    cert = p12.get_certificate()
    pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
    #print(cert_pem.load_privatekey(crypto.FILETYPE_PEM, "1234"))

    # Create and fill a X509Sore with trusted certs
    store = crypto.X509Store()
    for trusted_cert_pem in trusted_cert_pems:
    	trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
    store.add_cert(trusted_cert)

    # Create a X590StoreContext with the cert and trusted certs
    # and verify the the chain of trust
    store_ctx = crypto.X509StoreContext(store, certificate)
    # Returns None if certificate can be validated
    result = store_ctx.verify_certificate()

    if result is None:
    	print("OK")
    	return True
    else:
    	print("ERRO")
    	return False


#Carregar o ficheiro CA.cer
cert = crypto.load_certificate(crypto.FILETYPE_ASN1,
                                       open('CA.cer', "rb").read())

#Converter CA.cer em CA.pem
pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)


print("Cliente:")
verify_chain_of_trust("Cliente.p12", [pem])
print("Servidor:")
verify_chain_of_trust("Servidor.p12", [pem])