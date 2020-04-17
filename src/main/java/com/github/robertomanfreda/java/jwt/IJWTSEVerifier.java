package com.github.robertomanfreda.java.jwt;

import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;

interface IJWTSEVerifier {

    SignedJWT decryptToJWTS(String encryptedSignedJWT) throws Exception;

    boolean verifyJWTs(String encryptedSignedJWT) throws Exception;

    Payload decrypt(SignedJWT signedJWT);

    Payload verifyAndDecrypt(String encryptedSignedJWT) throws Exception;

}
