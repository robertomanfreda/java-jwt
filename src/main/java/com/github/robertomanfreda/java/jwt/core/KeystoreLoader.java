package com.github.robertomanfreda.java.jwt.core;

import com.github.robertomanfreda.java.jwt.exceptions.UnloadableKeystoreException;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@Slf4j
public class KeystoreLoader {

    private KeystoreLoader() {
    }

    static KeyPair loadFromUrl(URL downloadUrl, String downloadFileName) throws UnloadableKeystoreException {
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

    static KeyPair loadFromResource(String resourceName, String downloadFileName) throws UnloadableKeystoreException {
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

    static KeyPair loadFromPath(File zipFile, String resourceName) throws UnloadableKeystoreException {
        AtomicReference<String> alias = new AtomicReference<>();
        AtomicReference<String> password = new AtomicReference<>();
        AtomicReference<InputStream> keystoreIS = new AtomicReference<>();

        try {
            KeyPair keyPair = getKeyPair(alias, password, keystoreIS, new FileInputStream(zipFile));
            log.debug("Successfully loaded [{}] from FileSystem using path {}", resourceName, zipFile.getName());
            return keyPair;
        } catch (Exception e) {
            throw new UnloadableKeystoreException("Unable to load [" + resourceName + "] from resources folder\n" +
                    e.getMessage()
            );
        }
    }

    static KeyPair getKeyPair(AtomicReference<String> alias, AtomicReference<String> password,
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
