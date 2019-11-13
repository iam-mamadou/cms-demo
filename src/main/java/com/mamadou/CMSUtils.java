package com.mamadou;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public final class CMSUtils {

    private CMSUtils() {
    }

    public static X509Certificate loadCertificate(String certificateName) throws CertificateException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        var certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        var inputStream = loadResourceAsStream(certificateName);
        return (X509Certificate) certificateFactory.generateCertificate(inputStream);
    }

    public static PrivateKey loadPrivateKey(String name, String password, String alias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(loadResourceAsStream(name), password.toCharArray());
        Key privateKey = keystore.getKey(alias, password.toCharArray());
        return (PrivateKey) privateKey;
    }


    private static InputStream loadResourceAsStream(String fileName) {
        var classLoader = CMSUtils.class.getClassLoader();
        return classLoader.getResourceAsStream(fileName);
    }
}
