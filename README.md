# Java-jwt
A safe and fast library for JWTSE (Json Web Token Signed Encrypted) generation 

---

WARNING, WORK IN PROGRESS. MANY CHANGES ARE COMING!  

Java-jwt is build on top of the com.nimbusds:nimbus-jose-jwt library.    

Basically providing 2 methods that you can access instantiating a new `JavaJWT` object:
- `generate(...)`  
- `verifyAndDecypt(...)`

---

#### How to import using maven
```
<dependency>
    <groupId>com.github.robertomanfreda</groupId>
    <artifactId>java-jwt</artifactId>
    <version>1.1.0-RELEASE</version>
</dependency>
```  

---

#### Example of usage
###### Step 1 - Creating a safe keystore
Generating encrypted and signed Json Web Tokens needs some extra security... in order to create a `JavaJwt` object 
(that we will use for JWTSE generation and verification) you need to create 3 files:  
- `keyStore.p12` -> this file will be used to load a `KeyStore` Object in the Java code. Thanks to that object we can
    safely perform encryption, decryption and signing.
- `alias.txt`    -> this file contains the alias used during the keystore generation process.
- `password.txt` -> this file contains the password used during the keystore generation process.

You need to create these file separately and zip them in a zip folder named `keystore.zip`.  
  
You can use this one-liner to create all the necessary:  
`CURRENTTIME=$((date +%s%N)/1000000);
 mkdir "keystore_generation_$CURRENTTIME" && cd "keystore_generation_$CURRENTTIME";
 printf %s "<NEW_KEYSTORE_ALIAS_HERE>" > alias.txt;
 openssl req -x509 -newkey rsa:4096 -keyout private_key.pem -out public_key.der;
 openssl pkcs12 -export -out keyStore.p12 -inkey private_key.pem -in public_key.der -name "$(cat alias.txt)";
 printf %s "<NEW_KEYSTORE_PASSWORD_HERE>" > password.txt;
 zip keystore.zip alias.txt password.txt keyStore.p12;
 mv keystore.zip ../;
 cd ../;
 rm -rf "keystore_generation_$CURRENTTIME";`  
 
You just need to change the values for the following placeholders:  
- `<NEW_KEYSTORE_ALIAS_HERE>`
- `<NEW_KEYSTORE_PASSWORD_HERE>`  
  
This process will ask different times for a password, you should always type the same password that you inserted in the 
`<NEW_KEYSTORE_PASSWORD_HERE>` placeholder.    
At the end of the process (if nothing was wrong) you will find a file named `keystore.zip`, opening it should be 
present the 3 files listed above.

###### Step 2 - Creating new `JavaJWT` object
The `JavaJWT` class have a constructor who takes as input an `URL` object.     
If you want to load the keystore.zip file from a remote url you should use it:        
`JavaJWT javaJWT = new JavaJWT("http://localhost:1234/keystore.zip");`

If you want to try it you can run a temporary python http server (for serving static content) using this command:  
`mkdir keystore-test && cd keystore-test && cp <PATH_TO_keystore.zip_FILE> .; python -m http.server 1234;`  
Accessing from the web at `http://localhost:1234` you should see the content of the keystore_test folder.

Java-jwt will be able to download and parse the content through an HTTP GET request calling the specified url.  

###### Step 3 - JWTSE generation
After these steps you will be able to generate signed and encrypted Json Web Tokens, just like this:
`String jwtSE = javaJWT.generate("issuer", "audience", Map.of("key", "value"), 1000);`  

###### Step 4 - JWTSE verification
Just like the generation process the verification will be really simple:  
`Payload verifiedAndDecrypted = javaJwt.verifyAndDecrypt(jwtSE);`
And you will access the decrypted content through the `Payload` object methods.

--- 

#### Signing and Encryption details   
Java-jwt makes an extensive use of the com.nimbusds:nimbus-jose-jwt library and establish some guidelines.  
First of all we are using a strong keystore generated using openssl with RSA 4096 bit encryption, it's enough to 
prevent brute-force attacks on the private key.

There are 2 main processes during the generation of a Signed and Encrypted Json Web Token
1) Create a JTWS (Signed Json Web Token)
     sign using our key and `JWSAlgorithm.RS512` (RSASSA-PKCS-v1_5 using SHA-512 hash algorithm)  
     https://www.javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/8.5/com/nimbusds/jose/JWSAlgorithm.html#RS512
2) Encrypt the token generated at the step 1 actually creating a JWTE above a JWTS 
     encrypt using our key and `JWEAlgorithm.RSA_OAEP_256` (RSAES using Optimal Asymmetric Encryption Padding (OAEP) 
     (RFC 3447), with the SHA-256 hash function and the MGF1 with SHA-256 mask generation function)   
     https://www.javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/8.5/com/nimbusds/jose/JWEAlgorithm.html#RSA_OAEP_256

#### Decryption and verification details
This process is basically the opposed then the previous:  
1) Get a JWTS from the JWTSE  
2) Verify the signature  
3) Return a decrypted `Payload` object if the token is valid and not has been tampered with  


#### Releases
All releases are available at maven central: https://repo1.maven.org/maven2/com/github/robertomanfreda/java-jwt/