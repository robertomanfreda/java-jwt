package com.robertoman.java.jwt;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;

import java.security.interfaces.RSAPrivateKey;

class JWTSEVerifier {

    private final String secretKey;
    private final JWTEDecryptor jwTeDecryptor;
    private final JWTSVerifier jwTsVerifier;

    JWTSEVerifier(String secretKey, RSAPrivateKey rsaPrivateKey) {
        this.secretKey = secretKey;
        jwTeDecryptor = new JWTEDecryptor(rsaPrivateKey);
        jwTsVerifier = new JWTSVerifier();
    }

    Payload verify(String encryptedSignedJWT) throws Exception {
        boolean verified;
        SignedJWT signedJWT;

        try {
            JWEObject jweObjectEncrypted = JWEObject.parse(encryptedSignedJWT);
            JWEObject jweObjectDecrypted = jwTeDecryptor.decrypt(jweObjectEncrypted.serialize());

            signedJWT = jweObjectDecrypted.getPayload().toSignedJWT();

            String serialized = signedJWT.serialize();

            verified = jwTsVerifier.verify(serialized, secretKey);
        } catch (Exception e) {
            throw new InvalidTokenException("Error - " + e.getMessage());
        }

        if (verified) {
            return signedJWT.getPayload();
        }

        throw new InvalidTokenException("Invalid token or secret.");
    }
}
