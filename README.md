# create-keys-rsa
## Comandos Necesarios

### Encriptar
~~~
openssl rsautl -in txt.txt -out opensll.enc -pkcs -inkey private.pem -encrypt
~~~

### Desencriptar
~~~
openssl rsautl -in encrypt.enc -out t.txt -pkcs -inkey private.pem -decrypt
~~~


