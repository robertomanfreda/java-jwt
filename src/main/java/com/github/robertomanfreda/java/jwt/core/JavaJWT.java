package com.github.robertomanfreda.java.jwt.core;

import com.github.robertomanfreda.java.jwt.core.interfaces.IJWTSEGenerator;
import com.github.robertomanfreda.java.jwt.core.interfaces.IJWTSEVerifier;
import com.github.robertomanfreda.java.jwt.exceptions.UnloadableKeystoreException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.net.URL;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

@Slf4j
public class JavaJWT implements IJWTSEGenerator, IJWTSEVerifier {

    @Getter
    private URL downloadUrl;
    private String downloadFileName;

    @Getter
    private String resourceName;

    @Getter
    private Path resourcePath;

    private JWTSEGenerator generator;
    private JWTSEVerifier verifier;

    public JavaJWT(@NonNull URL downloadUrl) throws UnloadableKeystoreException {
        this.downloadUrl = downloadUrl;
        this.downloadFileName = downloadUrl.getFile().replace("/", "");
        log.debug("Trying to load [" + downloadFileName + "] from url [" + downloadUrl + "].");
        init(KeystoreLoader.loadFromUrl(downloadUrl, downloadFileName));
    }

    public JavaJWT(@NonNull String resourceName) throws UnloadableKeystoreException {
        this.resourceName = resourceName;
        log.debug("Trying to load [" + resourceName + "] from resources folder");
        init(KeystoreLoader.loadFromResource(resourceName, downloadFileName));
    }

    public JavaJWT(@NonNull Path resourcePath) throws UnloadableKeystoreException {
        this.resourcePath = resourcePath;
        File zipFile = resourcePath.toFile();
        log.debug("Trying to load [" + zipFile.getName() + "] from FileSystem");
        init(KeystoreLoader.loadFromPath(zipFile, downloadFileName));
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

}
