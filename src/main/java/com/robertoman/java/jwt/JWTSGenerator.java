package com.robertoman.java.jwt;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Map;

@RequiredArgsConstructor
class JWTSGenerator {

    @Getter
    private final String secretKey;

    SignedJWT generate(String issuer, String audience, Map<String, Object> claims, long ttlSeconds) throws Exception {
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build();
        JWTClaimsSet jwtClaimsSet = SigningUtils.generateClaimsSet(audience, claims, ttlSeconds, issuer);
        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        signedJWT.sign(new MACSigner(secretKey.getBytes()));

        return signedJWT;
    }

}
