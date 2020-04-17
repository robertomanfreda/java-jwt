package com.github.robertomanfreda.java.jwt;

import com.nimbusds.jwt.JWTClaimsSet;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

class SigningUtils {

    static JWTClaimsSet generateClaimsSet(String audience, Map<String, Object> claims, long ttlSeconds, String issuer) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date expiration = new Date(now + TimeUnit.SECONDS.toMillis(ttlSeconds));

        AtomicReference<JWTClaimsSet> jwtClaimsSet = new AtomicReference<>(new JWTClaimsSet.Builder().build());

        claims.forEach((key, value) ->
                jwtClaimsSet.set(new JWTClaimsSet.Builder(jwtClaimsSet.get()).claim(key, value).build())
        );

        return new JWTClaimsSet.Builder(jwtClaimsSet.get())
                .audience(audience)
                .expirationTime(expiration)
                .issuer(issuer)
                .issueTime(issuedAt)
                .jwtID(String.valueOf(UUID.randomUUID()))
                .notBeforeTime(issuedAt)
                .build();
    }

}
