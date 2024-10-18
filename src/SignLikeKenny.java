import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class SignLikeKenny {

    public static void main(String[] args) {

        try {
            // Add Bouncy Castle provider
            Security.addProvider(new BouncyCastleProvider());

            // 1. Read the private key from PEM file
            PrivateKey privateKey = readPrivateKeyFromPEM("~/DespicableMe/Gru.prv.pem");

            // For this example, we'll assume you have a corresponding certificate
            // In a real scenario, you'd load this from a file or keystore
            X509Certificate cert = readCertificateFromFile("~/DespicableMe/Gru.crt");
            X509Certificate caCert = readCertificateFromFile("~/DespicableMe/Gru_CA51-TEST-ONLY.crt");

            // 2. Create CMS signature using Brainpool curve
            byte[] data = "My data to sign".getBytes();
            CMSSignedData signedData = signData(data, privateKey, cert);

            // The signed data now contains the enveloped CAdES signature
            byte[] encodedSignedData = signedData.getEncoded();
            System.out.println("CAdES Signature created successfully.");
            System.out.println("Numb Bytes: " + encodedSignedData.length);
            writeToFile(encodedSignedData, "signed_data.asn1");
            System.out.println("Written to file.");
        } catch (Exception ex) {
            System.err.println(ex);
        }
        System.out.println("\nEnd.");
    }

    private static void writeToFile(byte[] data, String filename) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(data);
        }
    }

    private static PrivateKey readPrivateKeyFromPEM(String filename) throws Exception {
        try (FileReader keyReader = new FileReader(filename);
                PEMParser pemParser = new PEMParser(keyReader)) {

            Object object = pemParser.readObject();
            if (object instanceof PrivateKeyInfo) {
                PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) object;
                return new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
            }
            throw new IllegalArgumentException("Not a valid private key PEM file");
        }
    }

    private static X509Certificate readCertificateFromFile(String filename) throws Exception {
        try (FileInputStream fis = new FileInputStream(filename)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    private static CMSSignedData signData(byte[] data, PrivateKey privateKey, X509Certificate cert)
            throws CertificateEncodingException, OperatorCreationException, CMSException, IOException {
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC")
                .build(privateKey);

        CMSTypedData cmsData = new CMSProcessableByteArray(data);

        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();

        X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);

        cmsGenerator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                        .build(contentSigner, certHolder));

        cmsGenerator.addCertificate(certHolder);

        return cmsGenerator.generate(cmsData, true);
    }

    // This method is a placeholder. In a real scenario, you would load the
    // certificate
    // corresponding to your private key from a file or keystore.
    private static X509Certificate getCertificate(PrivateKey privateKey) {
        // Implementation depends on how you store/retrieve your certificate
        throw new UnsupportedOperationException("Certificate retrieval not implemented");
    }
}
