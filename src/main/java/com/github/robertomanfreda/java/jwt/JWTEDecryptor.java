package com.github.robertomanfreda.java.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import lombok.RequiredArgsConstructor;

import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;

@RequiredArgsConstructor
class JWTEDecryptor {

    private final RSAPrivateKey rsaPrivateKey;

    JWEObject decrypt(String jwtString) throws ParseException, JOSEException {
        EncryptedJWT jwt = EncryptedJWT.parse(jwtString);
        RSADecrypter decryptor = new RSADecrypter(rsaPrivateKey);
        jwt.decrypt(decryptor);
        return jwt;
    }

}
