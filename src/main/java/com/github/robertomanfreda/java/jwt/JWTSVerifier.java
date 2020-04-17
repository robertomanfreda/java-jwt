package com.github.robertomanfreda.java.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;

import java.text.ParseException;

@RequiredArgsConstructor
class JWTSVerifier {

    private final RSASSAVerifier rsassaVerifier;

    boolean verify(String jwt) throws ParseException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        boolean verified = signedJWT.verify(rsassaVerifier);

        if (verified) {
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature NOT verified");
        }

        return verified;
    }

}
