package com.mamadou;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

class CMSServiceTest {
    private static final String CA_CERT = "ssl/rootCA.crt.pem";
    private static final String CLIENT_CERT = "ssl/client.crt.pem";
    private static final String CLIENT_KEY = "ssl/client.pfx";
    private static final String CLIENT_KEY_PASSWORD = "client";
    private static final String CLIENT_KEY_ALIAS = "client";
    private static final String SELF_SIGNED_CERT = "ssl/self.crt.pem";
    private static final String SELF_SIGNED_KEY = "ssl/self.pfx";
    private static final String SELF_SIGNED_KEY_PASSWORD = "self";
    private static final String SELF_SIGNED_ALIAS = "self";


    @Test
    @DisplayName("Sign Content Using Client Certificate AND Verify Using CA Certificate")
    void signAndVerifyUsingCA() throws Exception {
        // given
        var content = "Hello World".getBytes();
        var certificate = CMSUtils.loadCertificate(CLIENT_CERT);
        var privateKey = CMSUtils.loadPrivateKey(CLIENT_KEY, CLIENT_KEY_PASSWORD, CLIENT_KEY_ALIAS);

        // when
        var cmsService = new CMSService();
        byte[] cmsSignedData = cmsService.sign(content, certificate, privateKey);

        // then
        X509Certificate caCertificate = CMSUtils.loadCertificate(CA_CERT);
        boolean isValid = cmsService.verify(cmsSignedData, caCertificate);
        assertThat(isValid).isTrue();
    }

    @Test()
    @DisplayName("Sign AND Verify Content Using the Same Certificate")
    void signAndVerifyUsingSelfSignedCert() throws Exception {
        // given
        var content = "Hello World".getBytes();
        var certificate = CMSUtils.loadCertificate(SELF_SIGNED_CERT);
        var privateKey = CMSUtils.loadPrivateKey(SELF_SIGNED_KEY, SELF_SIGNED_KEY_PASSWORD, SELF_SIGNED_ALIAS);

        // when
        var cmsService = new CMSService();
        byte[] cmsSignedData = cmsService.sign(content, certificate, privateKey);

        // then
        X509Certificate caCertificate = CMSUtils.loadCertificate(SELF_SIGNED_CERT);
        boolean isValid = cmsService.verify(cmsSignedData, caCertificate);
        assertThat(isValid).isTrue();
    }

    @Test
    @DisplayName("Sign Content Using Certificate that is not signed by CA")
    void signUsingInvalidCert() throws Exception {
        // given
        var content = "Hello World".getBytes();
        var certificate = CMSUtils.loadCertificate(SELF_SIGNED_CERT);
        var privateKey = CMSUtils.loadPrivateKey(SELF_SIGNED_KEY, SELF_SIGNED_KEY_PASSWORD, SELF_SIGNED_ALIAS);

        // when
        var cmsService = new CMSService();
        byte[] cmsSignedData = cmsService.sign(content, certificate, privateKey);

        // then
        X509Certificate caCertificate = CMSUtils.loadCertificate(CA_CERT);
        boolean isValid = cmsService.verify(cmsSignedData, caCertificate);
        assertThat(isValid).isFalse();
    }
}