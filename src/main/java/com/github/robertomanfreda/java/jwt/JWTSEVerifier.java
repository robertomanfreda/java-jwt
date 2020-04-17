package com.github.robertomanfreda.java.jwt;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

class JWTSEVerifier2 implements IJWTSEVerifier2 {

    private final JWTEDecrypter jwTeDecrypter;
    private final JWTSVerifier jwTsVerifier;

    JWTSEVerifier2(RSASSAVerifier rsassaVerifier, RSADecrypter rsaDecrypter) {
        jwTeDecrypter = new JWTEDecrypter(rsaDecrypter);
        jwTsVerifier = new JWTSVerifier(rsassaVerifier);
    }

    SignedJWT decryptToJWTS(String encryptedSignedJWT) throws Exception {
        JWEObject jweObjectEncrypted = JWEObject.parse(encryptedSignedJWT);
        JWEObject jweObjectDecrypted = jwTeDecrypter.decrypt(jweObjectEncrypted.serialize());
        return jweObjectDecrypted.getPayload().toSignedJWT();
    }

    boolean verifyJWTs(String encryptedSignedJWT) throws Exception {
        SignedJWT signedJWT = decryptToJWTS(encryptedSignedJWT);
        String serialized = signedJWT.serialize();
        return jwTsVerifier.verify(serialized);
    }

    Payload decrypt(SignedJWT signedJWT) {
        return signedJWT.getPayload();
    }

    Payload verifyAndDecrypt(String encryptedSignedJWT) throws Exception {
        SignedJWT signedJWT = decryptToJWTS(encryptedSignedJWT);
        boolean verified = verifyJWTs(encryptedSignedJWT);

        if (verified) {
            return decrypt(signedJWT);
        }

        throw new InvalidTokenException("Invalid.");
    }
}
