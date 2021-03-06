package com.github.robertomanfreda.java.jwt.core;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

import java.util.Map;

@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
class JWTSGenerator {

    private final RSASSASigner rsassaSigner;

    SignedJWT generate(String issuer, String audience, Map<String, Object> claims, long ttlSeconds) throws Exception {
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS512).type(JOSEObjectType.JWT).build();
        JWTClaimsSet jwtClaimsSet = ClaimSetBuilder.build(audience, claims, ttlSeconds, issuer);

        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        signedJWT.sign(rsassaSigner);

        return signedJWT;
    }

}
