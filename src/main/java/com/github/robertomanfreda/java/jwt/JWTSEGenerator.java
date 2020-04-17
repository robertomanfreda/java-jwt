package com.github.robertomanfreda.java.jwt;

import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.SignedJWT;

import java.util.Map;

class JWTSEGenerator implements IJWTSEGenerator {

    private final JWTSGenerator jwtsGenerator;
    private final JWTEEncrypter jwTeEncrypter;

    JWTSEGenerator(RSASSASigner rsassaSigner, RSAEncrypter rsaEncrypter) {
        jwtsGenerator = new JWTSGenerator(rsassaSigner);
        jwTeEncrypter = new JWTEEncrypter(rsaEncrypter);
    }

    @Override
    public String generate(String issuer, String audience, Map<String, Object> claims, long ttlSeconds)
            throws Exception {
        SignedJWT signedJWT = jwtsGenerator.generate(
                issuer, audience, claims, ttlSeconds
        );

        return jwTeEncrypter.encryptSigned(signedJWT);
    }

}
