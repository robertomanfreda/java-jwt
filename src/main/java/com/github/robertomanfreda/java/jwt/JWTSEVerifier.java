package com.github.robertomanfreda.java.jwt;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;

import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;

class JWTSEVerifier {

    private final RSAPublicKey rsaPublicKey;
    private final JWTEDecryptor jwTeDecryptor;
    private final JWTSVerifier jwTsVerifier;

    JWTSEVerifier(RSAPublicKey rsaPublicKey, PrivateKey privateKey) {
        this.rsaPublicKey = rsaPublicKey;
        jwTeDecryptor = new JWTEDecryptor(privateKey);
        jwTsVerifier = new JWTSVerifier();
    }

    Payload verifyAndDecrypt(String encryptedSignedJWT) throws Exception {
        boolean verified;
        SignedJWT signedJWT;

        try {
            JWEObject jweObjectEncrypted = JWEObject.parse(encryptedSignedJWT);
            JWEObject jweObjectDecrypted = jwTeDecryptor.decrypt(jweObjectEncrypted.serialize());

            signedJWT = jweObjectDecrypted.getPayload().toSignedJWT();

            String serialized = signedJWT.serialize();

            verified = jwTsVerifier.verify(serialized, rsaPublicKey);
        } catch (Exception e) {
            throw new InvalidTokenException("Error - " + e.getMessage());
        }

        if (verified) {
            return signedJWT.getPayload();
        }

        throw new InvalidTokenException("Invalid token or secret.");
    }
}
