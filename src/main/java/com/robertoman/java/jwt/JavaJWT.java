package com.robertoman.java.jwt;

import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import lombok.Getter;
import lombok.NonNull;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class JavaJWT {

    @Getter
    private final String secretKey;

    @Getter
    private final String downloadUrl;

    private final JWTSEGenerator generator;
    private final JWTSEVerifier verifier;

    public JavaJWT(@NonNull String secretKey, @NonNull String keystoreUrl) throws Exception {
        this.secretKey = secretKey;
        this.downloadUrl = keystoreUrl;
        KeyPair keyPair = loadKeyPair();

        if (null != keyPair) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            generator = new JWTSEGenerator(secretKey, new RSAEncrypter(rsaPublicKey));
            verifier = new JWTSEVerifier(secretKey, (RSAPrivateKey) keyPair.getPrivate());
        } else {
            throw new Exception("Trouble loading keystore");
        }
    }

    public String generate(String issuer, String audience, Map<String, Object> claims, long ttlSeconds)
            throws Exception {
        return generator.generate(issuer, audience, claims, ttlSeconds);
    }

    public Payload verify(String encryptedSignedJWT) throws Exception {
        return verifier.verify(encryptedSignedJWT);
    }

    private KeyPair loadKeyPair() throws Exception {
        String alias = null;
        String password = null;
        InputStream kis = null;

        URL url = new URL(downloadUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        InputStream is = connection.getInputStream();
        ZipInputStream zipIs = new ZipInputStream(is);
        ZipEntry zipEntry = zipIs.getNextEntry();

        while (zipEntry != null) {
            switch (zipEntry.getName()) {
                case "alias.txt":
                    alias = new String(zipIs.readAllBytes());
                    break;
                case "password.txt":
                    password = new String(zipIs.readAllBytes());
                    break;
                case "keyStore.p12":
                    kis = new ByteArrayInputStream(zipIs.readAllBytes());
                    break;
                default:
                    System.out.println("This file [" + zipEntry.getName() + "] is useless.");
            }

            zipIs.closeEntry();
            zipEntry = zipIs.getNextEntry();
        }

        if (null != alias && null != password && null != kis) {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(kis, password.toCharArray());

            Key key = keystore.getKey(alias, password.toCharArray());
            if (key instanceof PrivateKey) {
                Certificate cert = keystore.getCertificate(alias);
                PublicKey publicKey = cert.getPublicKey();

                return new KeyPair(publicKey, (PrivateKey) key);
            }
        }

        return null;
    }

}
