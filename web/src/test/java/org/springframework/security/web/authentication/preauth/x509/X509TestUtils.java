/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.preauth.x509;

import java.io.ByteArrayInputStream;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


/**
 * Certificate creation utility for use in X.509 tests.
 *
 * @author Luke Taylor
 */
public class X509TestUtils {
    //~ Methods ========================================================================================================

    /**
     * Builds an X.509 certificate. In human-readable form it is:
     * <pre>
     * Certificate:
     *  Data:
     *    Version: 3 (0x2)
     *    Serial Number: 1 (0x1)
     *    Signature Algorithm: sha1WithRSAEncryption
     *    Issuer: CN=Monkey Machine CA, C=UK, ST=Scotland, L=Glasgow,
     *      O=monkeymachine.co.uk/emailAddress=ca@monkeymachine
     *    Validity
     *      Not Before: Mar  6 23:28:22 2005 GMT
     *      Not After : Mar  6 23:28:22 2006 GMT
     *    Subject: C=UK, ST=Scotland, L=Glasgow, O=Monkey Machine Ltd,
     *      OU=Open Source Development Lab., CN=Luke Taylor/emailAddress=luke@monkeymachine
     *    Subject Public Key Info:
     *      Public Key Algorithm: rsaEncryption
     *      RSA Public Key: (512 bit)
     *          [omitted]
     *    X509v3 extensions:
     *      X509v3 Basic Constraints:
     *      CA:FALSE
     *      Netscape Cert Type:
     *      SSL Client
     *      X509v3 Key Usage:
     *      Digital Signature, Non Repudiation, Key Encipherment
     *      X509v3 Subject Key Identifier:
     *      6E:E6:5B:57:33:CF:0E:2F:15:C2:F4:DF:EC:14:BE:FB:CF:54:56:3C
     *      X509v3 Authority Key Identifier:
     *      keyid:AB:78:EC:AF:10:1B:8A:9B:1F:C7:B1:25:8F:16:28:F2:17:9A:AD:36
     *      DirName:/CN=Monkey Machine CA/C=UK/ST=Scotland/L=Glasgow/O=monkeymachine.co.uk/emailAddress=ca@monkeymachine
     *      serial:00
     *      Netscape CA Revocation Url:
     *      https://monkeymachine.co.uk/ca-crl.pem
     *  Signature Algorithm: sha1WithRSAEncryption
     *             [signature omitted]
     * </pre>
     */
    public static X509Certificate buildTestCertificate() throws Exception {
        String cert = "-----BEGIN CERTIFICATE-----\n"
            + "MIIEQTCCAymgAwIBAgIBATANBgkqhkiG9w0BAQUFADCBkzEaMBgGA1UEAxMRTW9u\n"
            + "a2V5IE1hY2hpbmUgQ0ExCzAJBgNVBAYTAlVLMREwDwYDVQQIEwhTY290bGFuZDEQ\n"
            + "MA4GA1UEBxMHR2xhc2dvdzEcMBoGA1UEChMTbW9ua2V5bWFjaGluZS5jby51azEl\n"
            + "MCMGCSqGSIb3DQEJARYWY2FAbW9ua2V5bWFjaGluZS5jby51azAeFw0wNTAzMDYy\n"
            + "MzI4MjJaFw0wNjAzMDYyMzI4MjJaMIGvMQswCQYDVQQGEwJVSzERMA8GA1UECBMI\n"
            + "U2NvdGxhbmQxEDAOBgNVBAcTB0dsYXNnb3cxGzAZBgNVBAoTEk1vbmtleSBNYWNo\n"
            + "aW5lIEx0ZDElMCMGA1UECxMcT3BlbiBTb3VyY2UgRGV2ZWxvcG1lbnQgTGFiLjEU\n"
            + "MBIGA1UEAxMLTHVrZSBUYXlsb3IxITAfBgkqhkiG9w0BCQEWEmx1a2VAbW9ua2V5\n"
            + "bWFjaGluZTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDItxZr07mm65ttYH7RMaVo\n"
            + "VeMCq4ptfn+GFFEk4+54OkDuh1CHlk87gEc1jx3ZpQPJRTJx31z3YkiAcP+RDzxr\n"
            + "AgMBAAGjggFIMIIBRDAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIHgDALBgNV\n"
            + "HQ8EBAMCBeAwHQYDVR0OBBYEFG7mW1czzw4vFcL03+wUvvvPVFY8MIHABgNVHSME\n"
            + "gbgwgbWAFKt47K8QG4qbH8exJY8WKPIXmq02oYGZpIGWMIGTMRowGAYDVQQDExFN\n"
            + "b25rZXkgTWFjaGluZSBDQTELMAkGA1UEBhMCVUsxETAPBgNVBAgTCFNjb3RsYW5k\n"
            + "MRAwDgYDVQQHEwdHbGFzZ293MRwwGgYDVQQKExNtb25rZXltYWNoaW5lLmNvLnVr\n"
            + "MSUwIwYJKoZIhvcNAQkBFhZjYUBtb25rZXltYWNoaW5lLmNvLnVrggEAMDUGCWCG\n"
            + "SAGG+EIBBAQoFiZodHRwczovL21vbmtleW1hY2hpbmUuY28udWsvY2EtY3JsLnBl\n"
            + "bTANBgkqhkiG9w0BAQUFAAOCAQEAZ961bEgm2rOq6QajRLeoljwXDnt0S9BGEWL4\n"
            + "PMU2FXDog9aaPwfmZ5fwKaSebwH4HckTp11xwe/D9uBZJQ74Uf80UL9z2eo0GaSR\n"
            + "nRB3QPZfRvop0I4oPvwViKt3puLsi9XSSJ1w9yswnIf89iONT7ZyssPg48Bojo8q\n"
            + "lcKwXuDRBWciODK/xWhvQbaegGJ1BtXcEHtvNjrUJLwSMDSr+U5oUYdMohG0h1iJ\n"
            + "R+JQc49I33o2cTc77wfEWLtVdXAyYY4GSJR6VfgvV40x85ItaNS3HHfT/aXU1x4m\n"
            + "W9YQkWlA6t0blGlC+ghTOY1JbgWnEfXMmVgg9a9cWaYQ+NQwqA==\n" + "-----END CERTIFICATE-----";

        ByteArrayInputStream in = new ByteArrayInputStream(cert.getBytes());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        return (X509Certificate) cf.generateCertificate(in);
    }

    /**
     * Builds an X.509 certificate with a subject DN where the CN field is at the end of the line.
     * The actual DN line is:
     * <pre>
     *  L=Cupertino,C=US,ST=CA,OU=Java Software,O=Sun Microsystems\, Inc,CN=Duke
     * </pre>
     *
     */
    public static X509Certificate buildTestCertificateWithCnAtEnd() throws Exception {
        String cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDjTCCAnWgAwIBAgIBATALBgkqhkiG9w0BAQswdTENMAsGA1UEAwwERHVrZTEe\n" +
                "MBwGA1UECgwVU3VuIE1pY3Jvc3lzdGVtcywgSW5jMRYwFAYDVQQLDA1KYXZhIFNv\n" +
                "ZnR3YXJlMQswCQYDVQQIDAJDQTELMAkGA1UEBhMCVVMxEjAQBgNVBAcMCUN1cGVy\n" +
                "dGlubzAeFw0xMjA1MTgxNDQ4MzBaFw0xMzA1MTgxNDQ4MzBaMHUxDTALBgNVBAMM\n" +
                "BER1a2UxHjAcBgNVBAoMFVN1biBNaWNyb3N5c3RlbXMsIEluYzEWMBQGA1UECwwN\n" +
                "SmF2YSBTb2Z0d2FyZTELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMRIwEAYDVQQH\n" +
                "DAlDdXBlcnRpbm8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGLaCx\n" +
                "Dy5oRJ/FelcoO/lAEApAhR4wxmUIu0guzN0Tx/cuWfyo4349NOxf5XfRcje37B//\n" +
                "hyMwK1Q/pRhRYtZlK+O+9tNCAupekmSxEw9wNsRXNJ18QTTvQRPReXhG8gOiGmU2\n" +
                "kpTVjpZURo/0WGuEyAWYzH99cQfUM92vIaGKq2fApNfwCULtFnAY9WPDZtwSZYhC\n" +
                "qSAoy6B1I2A3i+G5Ep++eCa9PZKCZIPWJiC5+nMmzwCOnQqcZlorsrQ+M+I4GgE2\n" +
                "Rryb/AeKoSPsrm4t0aWhFhKcuHpk3jfKhJhi5e+5bnY17pCoY9hx5EK3WqfKL/x1\n" +
                "3HKsPpf/MieRWiAdAgMBAAGjKjAoMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8E\n" +
                "DDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEAdAtXZYCdb7JKzfwY7vEO\n" +
                "9TOMyxxwxhxs+26urL2wQWqtRgHXopoi/GGSuZG5aPQcHWLoqZ1f7nZoWfKzJMKw\n" +
                "MOvaw6wSSkmEoEvdek3s/bH6Gp0spnykqtb+kunGr/XFxyBhHmfdSroEgzspslFh\n" +
                "Glqe/XfrQmFgPWd13GH8mqzSU1zc+0Ka7s68jcuNfz9ble5rT0IrdjRm5E64mVGk\n" +
                "aJTAO5N87ks5JjkDHDJzcyYRcIpqBGotJtyZTjGpIeAG8xLGlkSsUg88iUOchI7s\n" +
                "dOmse9mpgEjCb4kdZ0PnoxMFjsPR8AoGOz4A5vA19nKqWM8bxK9hqLGKsaiQpQg7\n" +
                "bA==\n" +
                "-----END CERTIFICATE-----\n";
        ByteArrayInputStream in = new ByteArrayInputStream(cert.getBytes());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        return (X509Certificate) cf.generateCertificate(in);
    }
}
