package com.mamadou;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class CMSService {

    public byte[] sign(byte[] content, X509Certificate signingCertificate, PrivateKey signingKey) {

        try {
            CMSTypedData cmsTypedData = new CMSProcessableByteArray(content);

            List<X509Certificate> certificates = List.of(signingCertificate);
            Store certificateStore = new JcaCertStore(certificates);

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);

            JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digestProvider());
            SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(contentSigner, signingCertificate);

            CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
            cmsSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);
            cmsSignedDataGenerator.addCertificates(certificateStore);
            CMSSignedData cmsData = cmsSignedDataGenerator.generate(cmsTypedData, true);
            return cmsData.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Error occurred while signing message", e);
        }
    }

    @SuppressWarnings("unchecked")
    public boolean verify(byte[] signedContent, X509Certificate rootCertificate) {
        try {
            CMSSignedData cmsSignedData = new CMSSignedData(signedContent);
            Store<X509CertificateHolder> cmsSignedDataCertificates = cmsSignedData.getCertificates();
            Collection<SignerInformation> cmsSignedDataSigners = cmsSignedData.getSignerInfos().getSigners();

            for (SignerInformation signer : cmsSignedDataSigners) {
                Collection<X509CertificateHolder> matches = cmsSignedDataCertificates.getMatches(signer.getSID());
                Iterator<X509CertificateHolder> iterator = matches.iterator();
                X509CertificateHolder x509CertificateHolder = iterator.next();
                PKIXCertPathBuilderResult result = validateAndBuildPath(toX509Certificate(x509CertificateHolder), rootCertificate);
                return signer.verify(signerInfoVerifier(result.getPublicKey()));
            }
            return false;
        } catch (Exception e) {
            System.out.println("Error occurred while verifying cms signed message: " + e);
            return false;
        }

    }

    private PKIXCertPathBuilderResult validateAndBuildPath(X509Certificate clientCertificate, X509Certificate rootCertificate) throws Exception {
        Set<TrustAnchor> trustAnchors = Set.of(new TrustAnchor(rootCertificate, null));

        List<X509Certificate> certificates = List.of(rootCertificate, clientCertificate);
        CollectionCertStoreParameters certStoreParams = new CollectionCertStoreParameters(certificates);
        CertStore certStore = CertStore.getInstance("Collection", certStoreParams);

        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setCertificate(clientCertificate);
        certSelector.setSubject(clientCertificate.getSubjectDN().getName());

        PKIXBuilderParameters certPathBuilderParams = new PKIXBuilderParameters(trustAnchors, certSelector);
        certPathBuilderParams.addCertStore(certStore);
        certPathBuilderParams.setRevocationEnabled(false);

        CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
        return (PKIXCertPathBuilderResult) certPathBuilder.build(certPathBuilderParams);
    }

    private DigestCalculatorProvider digestProvider() throws OperatorCreationException {
        return new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build();
    }

    private SignerInformationVerifier signerInfoVerifier(PublicKey signerPublicKey) throws OperatorCreationException, CertificateException {
        return new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signerPublicKey);
    }

    private X509Certificate toX509Certificate(X509CertificateHolder x509CertificateHolder) throws CertificateException {
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(x509CertificateHolder);
    }

}
