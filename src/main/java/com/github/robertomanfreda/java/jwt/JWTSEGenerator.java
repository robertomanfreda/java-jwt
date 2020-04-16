package com.github.robertomanfreda.java.jwt;

import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.SignedJWT;

import java.security.PrivateKey;
import java.util.Map;

class JWTSEGenerator {

    private final JWTSGenerator jwtsGenerator;
    private final JWTEEncryptor jwTeEncryptor;

    JWTSEGenerator(PrivateKey privateKey, RSAEncrypter rsaEncrypter) {
        jwtsGenerator = new JWTSGenerator(privateKey);
        jwTeEncryptor = new JWTEEncryptor(rsaEncrypter);
    }

    String generate(String issuer, String audience, Map<String, Object> claims, long ttlSeconds)
            throws Exception {
        SignedJWT signedJWT = jwtsGenerator.generate(
                issuer, audience, claims, ttlSeconds
        );

        return jwTeEncryptor.encryptSigned(signedJWT);
    }

}
