package com.github.robertomanfreda.java.jwt;

import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Slf4j
public class JavaJWT implements IJWTSEGenerator, IJWTSEVerifier {

    @Getter
    private URL downloadUrl;
    private String downloadFileName;

    @Getter
    private String resourceName;

    private JWTSEGenerator generator;
    private JWTSEVerifier verifier;

    public JavaJWT(@NonNull URL downloadUrl) throws UnloadableKeystoreException {
        this.downloadUrl = downloadUrl;
        this.downloadFileName = downloadUrl.getFile().replace("/", "");
        log.debug("Trying to load [" + downloadFileName + "] from url [" + downloadUrl + "].");
        init(loadFromUrl());
    }

    public JavaJWT(@NonNull String resourceName) throws UnloadableKeystoreException {
        this.resourceName = resourceName;
        log.debug("Trying to load [" + resourceName + "] from resources folder");
        init(loadFromResource());
    }

    // Generator wrapper methods
    @Override
    public String generate(String issuer, String audience, Map<String, Object> claims, long ttlSeconds) throws Exception {
        return generator.generate(issuer, audience, claims, ttlSeconds);
    }

    // Verifier wrapper methods
    @Override
    public SignedJWT decryptToJWTS(String encryptedSignedJWT) throws Exception {
        return verifier.decryptToJWTS(encryptedSignedJWT);
    }

    @Override
    public boolean verifyJWTs(String encryptedSignedJWT) throws Exception {
        return verifier.verifyJWTs(encryptedSignedJWT);
    }

    @Override
    public Payload decrypt(SignedJWT signedJWT) {
        return verifier.decrypt(signedJWT);
    }

    @Override
    public Payload verifyAndDecrypt(String encryptedSignedJWT) throws Exception {
        return verifier.verifyAndDecrypt(encryptedSignedJWT);
    }

    private void init(KeyPair keyPair) {
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

        RSASSASigner rsassaSigner = new RSASSASigner(privateKey);
        RSAEncrypter rsaEncrypter = new RSAEncrypter(rsaPublicKey);
        generator = new JWTSEGenerator(rsassaSigner, rsaEncrypter);

        RSASSAVerifier rsassaVerifier = new RSASSAVerifier(rsaPublicKey);
        RSADecrypter rsaDecrypter = new RSADecrypter(privateKey);
        verifier = new JWTSEVerifier(rsassaVerifier, rsaDecrypter);
    }

    private KeyPair loadFromUrl() throws UnloadableKeystoreException {
        AtomicReference<String> alias = new AtomicReference<>();
        AtomicReference<String> password = new AtomicReference<>();
        AtomicReference<InputStream> keystoreIS = new AtomicReference<>();

        try {
            HttpURLConnection connection = (HttpURLConnection) downloadUrl.openConnection();
            connection.setRequestMethod("GET");
            InputStream inputStream = connection.getInputStream();

            KeyPair keyPair = getKeyPair(alias, password, keystoreIS, inputStream);

            log.debug("Successfully loaded [" + downloadFileName + "] from the specified url [" + downloadUrl + "]");

            return keyPair;
        } catch (Exception e) {
            throw new UnloadableKeystoreException("Unable to load [" + downloadFileName + "] from the specified url [" +
                    downloadUrl + "]\n" + e.getMessage()
            );
        }
    }

    private KeyPair loadFromResource() throws UnloadableKeystoreException {
        AtomicReference<String> alias = new AtomicReference<>();
        AtomicReference<String> password = new AtomicReference<>();
        AtomicReference<InputStream> keystoreIS = new AtomicReference<>();

        try {
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            InputStream inputStream = classLoader.getResourceAsStream(resourceName);

            KeyPair keyPair = getKeyPair(alias, password, keystoreIS, inputStream);

            log.debug("Successfully loaded [" + downloadFileName + "] from resources folder");

            return keyPair;
        } catch (Exception e) {
            throw new UnloadableKeystoreException("Unable to load [" + resourceName + "] from resources folder\n" +
                    e.getMessage()
            );
        }
    }

    private KeyPair getKeyPair(AtomicReference<String> alias, AtomicReference<String> password,
                               AtomicReference<InputStream> keystoreIS, InputStream inputStream)
            throws UnloadableKeystoreException {
        try {
            ZipInputStream zipIs = new ZipInputStream(inputStream);
            ZipEntry zipEntry = zipIs.getNextEntry();

            while (null != zipEntry) {
                // TODO implement files content validation
                switch (zipEntry.getName().toLowerCase()) {
                    case "alias.txt":
                        alias.set(new String(zipIs.readAllBytes()));
                        break;
                    case "password.txt":
                        password.set(new String(zipIs.readAllBytes()));
                        break;
                    case "keystore.p12":
                        keystoreIS.set(new ByteArrayInputStream(zipIs.readAllBytes()));
                        break;
                    default:
                        log.warn("This file [" + zipEntry.getName() + "] is useless, just delete it. " +
                                "Needed files are [alias.txt, password.txt, keyStore.p12]."
                        );
                }

                zipIs.closeEntry();
                zipEntry = zipIs.getNextEntry();
            }

            if (null != alias && null != password && null != keystoreIS) {
                KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
                keystore.load(keystoreIS.get(), password.get().toCharArray());

                Key key = keystore.getKey(alias.get(), password.get().toCharArray());
                if (key instanceof PrivateKey) {
                    Certificate cert = keystore.getCertificate(alias.get());
                    return new KeyPair(cert.getPublicKey(), (PrivateKey) key);
                }
            }
        } catch (Exception e) {
            throw new UnloadableKeystoreException("Unable to load zip file.\n" + e.getMessage());
        }

        throw new UnloadableKeystoreException("An error occurred trying to load KeyPair.");
    }

}
