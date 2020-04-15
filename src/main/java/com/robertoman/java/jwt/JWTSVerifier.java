package com.robertoman.java.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.NoArgsConstructor;

import java.text.ParseException;

@NoArgsConstructor
class JWTSVerifier {

    boolean verify(String jwt, String secretKey) throws ParseException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        JWSVerifier jwsVerifier = new MACVerifier(secretKey.getBytes());

        boolean verified = signedJWT.verify(jwsVerifier);

        if (verified) {
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature NOT verified");
        }

        return verified;
    }

}
