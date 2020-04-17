package com.github.robertomanfreda.java.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import lombok.RequiredArgsConstructor;

import java.text.ParseException;

@RequiredArgsConstructor
class JWTEDecrypter {

    private final RSADecrypter rsaDecrypter;

    JWEObject decrypt(String jwtString) throws ParseException, JOSEException {
        EncryptedJWT jwt = EncryptedJWT.parse(jwtString);
        jwt.decrypt(rsaDecrypter);
        return jwt;
    }

}
