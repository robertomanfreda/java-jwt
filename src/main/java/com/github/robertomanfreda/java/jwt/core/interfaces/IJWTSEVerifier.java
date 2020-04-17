package com.github.robertomanfreda.java.jwt.core.interfaces;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;

public interface IJWTSEVerifier {

    SignedJWT decryptToJWTS(String encryptedSignedJWT) throws Exception;

    boolean verifyJWTs(String encryptedSignedJWT) throws Exception;

    Payload decrypt(SignedJWT signedJWT);

    Payload verifyAndDecrypt(String encryptedSignedJWT) throws Exception;

}
