package com.robertoman.java.jwt;

import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.SignedJWT;

import java.util.Map;

class JWTSEGenerator {

    private final JWTSGenerator jwtsGenerator;
    private final JWTEEncryptor jwTeEncryptor;

    JWTSEGenerator(String secretKey, RSAEncrypter rsaEncrypter) {
        jwtsGenerator = new JWTSGenerator(secretKey);
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
