package com.robertoman.java.jwt;

import com.nimbusds.jose.Payload;

import java.util.Map;

public class Main {
    public static void main(String[] args) throws Exception {
        String secret = "12345678912345678912345678912345";

        System.out.println();
        JavaJWT javaJwt = new JavaJWT(secret, "http://localhost/keystore.zip");


        // generate
        String generated = javaJwt.generate(
                "test", "test", Map.of("test", 1), 100
        );
        System.out.println(generated);
        System.out.println();

        // verify
        Payload verified = javaJwt.verify(generated);
        System.out.println(verified.toString());
    }
}
