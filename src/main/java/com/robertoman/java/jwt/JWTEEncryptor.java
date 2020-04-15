package com.robertoman.java.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
class JWTEEncryptor {

    private final RSAEncrypter rsaEncrypter;

    String encryptSigned(SignedJWT signedJWT) throws JOSEException {
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .contentType("JWT")
                        .build(),
                new Payload(signedJWT)
        );

        jweObject.encrypt(rsaEncrypter);

        return jweObject.serialize();
    }

}
