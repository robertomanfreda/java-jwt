package com.github.robertomanfreda.java.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.NoArgsConstructor;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

@NoArgsConstructor
class JWTSVerifier {

    boolean verify(String jwt, RSAPublicKey rsaPublicKey) throws ParseException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        JWSVerifier jwsVerifier = new RSASSAVerifier(rsaPublicKey);

        boolean verified = signedJWT.verify(jwsVerifier);

        if (verified) {
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature NOT verified");
        }

        return verified;
    }

}
