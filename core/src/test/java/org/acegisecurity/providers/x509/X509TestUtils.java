package net.sf.acegisecurity.providers.x509;

import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;

/**
 * @author Luke Taylor
 */
public class X509TestUtils {

    public static X509AuthenticationToken createToken() throws Exception {
        return new X509AuthenticationToken(buildTestCertificate());
    }
    /**
      * Builds an X.509 certificate. In human-readable form it is:
      * <pre>
      * Certificate:
      *   Data:
      *      Version: 3 (0x2)
      *      Serial Number: 1 (0x1)
      *      Signature Algorithm: sha1WithRSAEncryption
      *      Issuer: CN=Monkey Machine CA, C=UK, ST=Scotland, L=Glasgow,
      *          O=monkeymachine.co.uk/emailAddress=ca@monkeymachine.co.uk
      *      Validity
      *          Not Before: Mar  6 23:28:22 2005 GMT
      *          Not After : Mar  6 23:28:22 2006 GMT
      *      Subject: C=UK, ST=Scotland, L=Glasgow, O=Monkey Machine Ltd,
      *          OU=Open Source Development Lab., CN=Luke Taylor/emailAddress=luke@monkeymachine
      *      Subject Public Key Info:
      *          Public Key Algorithm: rsaEncryption
      *          RSA Public Key: (512 bit)
      *              [omitted]
      *      X509v3 extensions:
      *          X509v3 Basic Constraints:
      *          CA:FALSE
      *          Netscape Cert Type:
      *          SSL Client
      *          X509v3 Key Usage:
      *          Digital Signature, Non Repudiation, Key Encipherment
      *          X509v3 Subject Key Identifier:
      *          6E:E6:5B:57:33:CF:0E:2F:15:C2:F4:DF:EC:14:BE:FB:CF:54:56:3C
      *          X509v3 Authority Key Identifier:
      *          keyid:AB:78:EC:AF:10:1B:8A:9B:1F:C7:B1:25:8F:16:28:F2:17:9A:AD:36
      *          DirName:/CN=Monkey Machine CA/C=UK/ST=Scotland/L=Glasgow/O=monkeymachine.co.uk/emailAddress=ca@monkeymachine.co.uk
      *          serial:00
      *          Netscape CA Revocation Url:
      *          https://monkeymachine.co.uk/ca-crl.pem
      *   Signature Algorithm: sha1WithRSAEncryption
      *             [signature omitted]
      * </pre>
      */
     public static X509Certificate buildTestCertificate() throws Exception
     {
         String cert = "-----BEGIN CERTIFICATE-----\n" +
                 "MIIEQTCCAymgAwIBAgIBATANBgkqhkiG9w0BAQUFADCBkzEaMBgGA1UEAxMRTW9u\n" +
                 "a2V5IE1hY2hpbmUgQ0ExCzAJBgNVBAYTAlVLMREwDwYDVQQIEwhTY290bGFuZDEQ\n" +
                 "MA4GA1UEBxMHR2xhc2dvdzEcMBoGA1UEChMTbW9ua2V5bWFjaGluZS5jby51azEl\n" +
                 "MCMGCSqGSIb3DQEJARYWY2FAbW9ua2V5bWFjaGluZS5jby51azAeFw0wNTAzMDYy\n" +
                 "MzI4MjJaFw0wNjAzMDYyMzI4MjJaMIGvMQswCQYDVQQGEwJVSzERMA8GA1UECBMI\n" +
                 "U2NvdGxhbmQxEDAOBgNVBAcTB0dsYXNnb3cxGzAZBgNVBAoTEk1vbmtleSBNYWNo\n" +
                 "aW5lIEx0ZDElMCMGA1UECxMcT3BlbiBTb3VyY2UgRGV2ZWxvcG1lbnQgTGFiLjEU\n" +
                 "MBIGA1UEAxMLTHVrZSBUYXlsb3IxITAfBgkqhkiG9w0BCQEWEmx1a2VAbW9ua2V5\n" +
                 "bWFjaGluZTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDItxZr07mm65ttYH7RMaVo\n" +
                 "VeMCq4ptfn+GFFEk4+54OkDuh1CHlk87gEc1jx3ZpQPJRTJx31z3YkiAcP+RDzxr\n" +
                 "AgMBAAGjggFIMIIBRDAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIHgDALBgNV\n" +
                 "HQ8EBAMCBeAwHQYDVR0OBBYEFG7mW1czzw4vFcL03+wUvvvPVFY8MIHABgNVHSME\n" +
                 "gbgwgbWAFKt47K8QG4qbH8exJY8WKPIXmq02oYGZpIGWMIGTMRowGAYDVQQDExFN\n" +
                 "b25rZXkgTWFjaGluZSBDQTELMAkGA1UEBhMCVUsxETAPBgNVBAgTCFNjb3RsYW5k\n" +
                 "MRAwDgYDVQQHEwdHbGFzZ293MRwwGgYDVQQKExNtb25rZXltYWNoaW5lLmNvLnVr\n" +
                 "MSUwIwYJKoZIhvcNAQkBFhZjYUBtb25rZXltYWNoaW5lLmNvLnVrggEAMDUGCWCG\n" +
                 "SAGG+EIBBAQoFiZodHRwczovL21vbmtleW1hY2hpbmUuY28udWsvY2EtY3JsLnBl\n" +
                 "bTANBgkqhkiG9w0BAQUFAAOCAQEAZ961bEgm2rOq6QajRLeoljwXDnt0S9BGEWL4\n" +
                 "PMU2FXDog9aaPwfmZ5fwKaSebwH4HckTp11xwe/D9uBZJQ74Uf80UL9z2eo0GaSR\n" +
                 "nRB3QPZfRvop0I4oPvwViKt3puLsi9XSSJ1w9yswnIf89iONT7ZyssPg48Bojo8q\n" +
                 "lcKwXuDRBWciODK/xWhvQbaegGJ1BtXcEHtvNjrUJLwSMDSr+U5oUYdMohG0h1iJ\n" +
                 "R+JQc49I33o2cTc77wfEWLtVdXAyYY4GSJR6VfgvV40x85ItaNS3HHfT/aXU1x4m\n" +
                 "W9YQkWlA6t0blGlC+ghTOY1JbgWnEfXMmVgg9a9cWaYQ+NQwqA==\n" +
                 "-----END CERTIFICATE-----";

         ByteArrayInputStream in = new ByteArrayInputStream(cert.getBytes());
         CertificateFactory cf = CertificateFactory.getInstance("X.509");
         return (X509Certificate)cf.generateCertificate(in);

     }

}
