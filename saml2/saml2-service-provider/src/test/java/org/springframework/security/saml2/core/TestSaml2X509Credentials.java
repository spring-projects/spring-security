/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.saml2.core;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.opensaml.security.crypto.KeySupport;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2X509Credential.Saml2X509CredentialType;

public final class TestSaml2X509Credentials {

	private TestSaml2X509Credentials() {
	}

	public static Saml2X509Credential assertingPartySigningCredential() {
		return new Saml2X509Credential(idpPrivateKey(), idpCertificate(), Saml2X509CredentialType.SIGNING);
	}

	public static Saml2X509Credential assertingPartyEncryptingCredential() {
		return new Saml2X509Credential(spCertificate(), Saml2X509CredentialType.ENCRYPTION);
	}

	public static Saml2X509Credential assertingPartyPrivateCredential() {
		return new Saml2X509Credential(idpPrivateKey(), idpCertificate(), Saml2X509CredentialType.SIGNING,
				Saml2X509CredentialType.DECRYPTION);
	}

	public static Saml2X509Credential relyingPartyVerifyingCredential() {
		return new Saml2X509Credential(idpCertificate(), Saml2X509CredentialType.VERIFICATION);
	}

	public static Saml2X509Credential relyingPartyEncryptingCredential() {
		return new Saml2X509Credential(idpCertificate(), Saml2X509CredentialType.ENCRYPTION);
	}

	public static Saml2X509Credential relyingPartySigningCredential() {
		return new Saml2X509Credential(spPrivateKey(), spCertificate(), Saml2X509CredentialType.SIGNING);
	}

	public static Saml2X509Credential relyingPartyDecryptingCredential() {
		return new Saml2X509Credential(spPrivateKey(), spCertificate(), Saml2X509CredentialType.DECRYPTION);
	}

	public static Saml2X509Credential altPublicCredential() {
		return new Saml2X509Credential(altCertificate(), Saml2X509CredentialType.VERIFICATION,
				Saml2X509CredentialType.ENCRYPTION);
	}

	public static Saml2X509Credential altPrivateCredential() {
		return new Saml2X509Credential(altPrivateKey(), altCertificate(), Saml2X509CredentialType.SIGNING,
				Saml2X509CredentialType.DECRYPTION);
	}

	private static X509Certificate certificate(String cert) {
		ByteArrayInputStream certBytes = new ByteArrayInputStream(cert.getBytes());
		try {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certBytes);
		}
		catch (CertificateException ex) {
			throw new Saml2Exception(ex);
		}
	}

	private static PrivateKey privateKey(String key) {
		try {
			return KeySupport.decodePrivateKey(key.getBytes(StandardCharsets.UTF_8), new char[0]);
		}
		catch (KeyException ex) {
			throw new Saml2Exception(ex);
		}
	}

	private static X509Certificate idpCertificate() {
		return certificate(
				"-----BEGIN CERTIFICATE-----\n" + "MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYD\n"
						+ "VQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYD\n"
						+ "VQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwX\n"
						+ "c2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0Bw\n"
						+ "aXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJ\n"
						+ "BgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAa\n"
						+ "BgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQD\n"
						+ "DBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlr\n"
						+ "QHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62\n"
						+ "E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz\n"
						+ "2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWW\n"
						+ "RDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQ\n"
						+ "nX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5\n"
						+ "cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gph\n"
						+ "iJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5\n"
						+ "ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTAD\n"
						+ "AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduO\n"
						+ "nRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+v\n"
						+ "ZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLu\n"
						+ "xbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6z\n"
						+ "V9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3\n"
						+ "lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk\n" + "-----END CERTIFICATE-----\n");
	}

	private static PrivateKey idpPrivateKey() {
		return privateKey(
				"-----BEGIN PRIVATE KEY-----\n" + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4cn62E1xLqpN3\n"
						+ "4PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZX\n"
						+ "W+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHE\n"
						+ "fDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7h\n"
						+ "Z6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/T\n"
						+ "Xy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7\n"
						+ "I+J5lS8VAgMBAAECggEBAKyxBlIS7mcp3chvq0RF7B3PHFJMMzkwE+t3pLJcs4cZ\n"
						+ "nezh/KbREfP70QjXzk/llnZCvxeIs5vRu24vbdBm79qLHqBuHp8XfHHtuo2AfoAQ\n"
						+ "l4h047Xc/+TKMivnPQ0jX9qqndKDLqZDf5wnbslDmlskvF0a/MjsLU0TxtOfo+dB\n"
						+ "t55FW11cGqxZwhS5Gnr+cbw3OkHz23b9gEOt9qfwPVepeysbmm9FjU+k4yVa7rAN\n"
						+ "xcbzVb6Y7GCITe2tgvvEHmjB9BLmWrH3mZ3Af17YU/iN6TrpPd6Sj3QoS+2wGtAe\n"
						+ "HbUs3CKJu7bIHcj4poal6Kh8519S+erJTtqQ8M0ZiEECgYEA43hLYAPaUueFkdfh\n"
						+ "9K/7ClH6436CUH3VdizwUXi26fdhhV/I/ot6zLfU2mgEHU22LBECWQGtAFm8kv0P\n"
						+ "zPn+qjaR3e62l5PIlSYbnkIidzoDZ2ztu4jF5LgStlTJQPteFEGgZVl5o9DaSZOq\n"
						+ "Yd7G3XqXuQ1VGMW58G5FYJPtA1cCgYEAz5TPUtK+R2KXHMjUwlGY9AefQYRYmyX2\n"
						+ "Tn/OFgKvY8lpAkMrhPKONq7SMYc8E9v9G7A0dIOXvW7QOYSapNhKU+np3lUafR5F\n"
						+ "4ZN0bxZ9qjHbn3AMYeraKjeutHvlLtbHdIc1j3sxe/EzltRsYmiqLdEBW0p6hwWg\n"
						+ "tyGhYWVyaXMCgYAfDOKtHpmEy5nOCLwNXKBWDk7DExfSyPqEgSnk1SeS1HP5ctPK\n"
						+ "+1st6sIhdiVpopwFc+TwJWxqKdW18tlfT5jVv1E2DEnccw3kXilS9xAhWkfwrEvf\n"
						+ "V5I74GydewFl32o+NZ8hdo9GL1I8zO1rIq/et8dSOWGuWf9BtKu/vTGTTQKBgFxU\n"
						+ "VjsCnbvmsEwPUAL2hE/WrBFaKocnxXx5AFNt8lEyHtDwy4Sg1nygGcIJ4sD6koQk\n"
						+ "RdClT3LkvR04TAiSY80bN/i6ZcPNGUwSaDGZEWAIOSWbkwZijZNFnSGOEgxZX/IG\n"
						+ "yd39766vREEMTwEeiMNEOZQ/dmxkJm4OOVe25cLdAoGACOtPnq1Fxay80UYBf4rQ\n"
						+ "+bJ9yX1ulB8WIree1hD7OHSB2lRHxrVYWrglrTvkh63Lgx+EcsTV788OsvAVfPPz\n"
						+ "BZrn8SdDlQqalMxUBYEFwnsYD3cQ8yOUnijFVC4xNcdDv8OIqVgSk4KKxU5AshaA\n"
						+ "xk6Mox+u8Cc2eAK12H13i+8=\n" + "-----END PRIVATE KEY-----\n");
	}

	private static X509Certificate spCertificate() {
		return certificate(
				"-----BEGIN CERTIFICATE-----\n" + "MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n"
						+ "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n"
						+ "A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n"
						+ "DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n"
						+ "MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n"
						+ "MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n"
						+ "TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n"
						+ "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n"
						+ "vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n"
						+ "+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n"
						+ "y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n"
						+ "XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n"
						+ "qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n"
						+ "RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B\n" + "-----END CERTIFICATE-----");
	}

	private static PrivateKey spPrivateKey() {
		return privateKey(
				"-----BEGIN PRIVATE KEY-----\n" + "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANG7v8QjQGU3MwQE\n"
						+ "VUBxvH6Uuiy/MhZT7TV0ZNjyAF2ExA1gpn3aUxx6jYK5UnrpxRRE/KbeLucYbOhK\n"
						+ "cDECt77Rggz5TStrOta0BQTvfluRyoQtmQ5Nkt6Vqg7O2ZapFt7k64Sal7AftzH6\n"
						+ "Q2BxWN1y04bLdDrH4jipqRj/2qEFAgMBAAECgYEAj4ExY1jjdN3iEDuOwXuRB+Nn\n"
						+ "x7pC4TgntE2huzdKvLJdGvIouTArce8A6JM5NlTBvm69mMepvAHgcsiMH1zGr5J5\n"
						+ "wJz23mGOyhM1veON41/DJTVG+cxq4soUZhdYy3bpOuXGMAaJ8QLMbQQoivllNihd\n"
						+ "vwH0rNSK8LTYWWPZYIECQQDxct+TFX1VsQ1eo41K0T4fu2rWUaxlvjUGhK6HxTmY\n"
						+ "8OMJptunGRJL1CUjIb45Uz7SP8TPz5FwhXWsLfS182kRAkEA3l+Qd9C9gdpUh1uX\n"
						+ "oPSNIxn5hFUrSTW1EwP9QH9vhwb5Vr8Jrd5ei678WYDLjUcx648RjkjhU9jSMzIx\n"
						+ "EGvYtQJBAMm/i9NR7IVyyNIgZUpz5q4LI21rl1r4gUQuD8vA36zM81i4ROeuCly0\n"
						+ "KkfdxR4PUfnKcQCX11YnHjk9uTFj75ECQEFY/gBnxDjzqyF35hAzrYIiMPQVfznt\n"
						+ "YX/sDTE2AdVBVGaMj1Cb51bPHnNC6Q5kXKQnj/YrLqRQND09Q7ParX0CQQC5NxZr\n"
						+ "9jKqhHj8yQD6PlXTsY4Occ7DH6/IoDenfdEVD5qlet0zmd50HatN2Jiqm5ubN7CM\n" + "INrtuLp4YHbgk1mi\n"
						+ "-----END PRIVATE KEY-----");
	}

	private static X509Certificate altCertificate() {
		return certificate(
				"-----BEGIN CERTIFICATE-----\n" + "MIICkDCCAfkCFEstVfmWSFQp/j88GaMUwqVK72adMA0GCSqGSIb3DQEBCwUAMIGG\n"
						+ "MQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjESMBAGA1UEBwwJVmFu\n"
						+ "Y291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FNTDEMMAoGA1UECwwD\n"
						+ "YWx0MSEwHwYDVQQDDBhhbHQuc3ByaW5nLnNlY3VyaXR5LnNhbWwwHhcNMjIwMjEw\n"
						+ "MTY1ODA4WhcNMzIwMjEwMTY1ODA4WjCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgM\n"
						+ "Cldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsGA1UECgwUU3ByaW5n\n"
						+ "IFNlY3VyaXR5IFNBTUwxDDAKBgNVBAsMA2FsdDEhMB8GA1UEAwwYYWx0LnNwcmlu\n"
						+ "Zy5zZWN1cml0eS5zYW1sMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9ZGWj\n"
						+ "TPDsymQCJL044py4xLsBI/S9RvzNeR9oD/tHyoxCE+YZzjf0PyBtwqKzkKWqCPf4\n"
						+ "XGUYHfEpkM5kJYwCW8TsOx5fnwLIQweiPqjYrBr/O0IjHMqYG9HlR/ros7iBt4ab\n"
						+ "EGUu/B9yYg1YRYPxKQ6TNP3AD+9tBT8TsFFyjwIDAQABMA0GCSqGSIb3DQEBCwUA\n"
						+ "A4GBAKJf2VHLjkCHRxlbWn63jGiquq3ENYgd1JS0DZ3ggFmuc6zQiqxzRGtArIDZ\n"
						+ "0jH5nrG0jcvO0fqDqBQh0iT8thfUnkViAQvACZ9a+0x0NzUicJ+Ra51c8Z2enqbg\n"
						+ "pXy+ga67HcAXrDekm1MCGCgiEb/Cgl41lsideqhC8Efl7PRN\n" + "-----END CERTIFICATE-----");
	}

	private static PrivateKey altPrivateKey() {
		return privateKey(
				"-----BEGIN PRIVATE KEY-----\n" + "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAL1kZaNM8OzKZAIk\n"
						+ "vTjinLjEuwEj9L1G/M15H2gP+0fKjEIT5hnON/Q/IG3CorOQpaoI9/hcZRgd8SmQ\n"
						+ "zmQljAJbxOw7Hl+fAshDB6I+qNisGv87QiMcypgb0eVH+uizuIG3hpsQZS78H3Ji\n"
						+ "DVhFg/EpDpM0/cAP720FPxOwUXKPAgMBAAECgYEApYKslAZ0cer5dSoYNzNLFOnQ\n"
						+ "J1H92r/Dw+k6+h0lUvr+keyD5T9jhM76DxHOUDBzpmIKGoDcVDQugk2rILfzXsQA\n"
						+ "JtwvDRJk32Z02Vt0jb7t/WUOOQhjKCjQuv9/tOx90GCl0VxYG69UOjaMRWrlg/i9\n"
						+ "6/zcTRIahIn5XxF0psECQQD7ivJCpDbOLJGsc8gNJR4cvjZ1q0mHIOrbKqJC0y1n\n"
						+ "5DrzGEflPeyCUwnOKNp9HJQP8gmZzXfj0JM9KsjpiUChAkEAwL+FmhDoTiqStIrH\n"
						+ "h9Kdnsev//imMmRHxjwDhntYvqavUsISRmY3imd8inoYq5dzWQMzBtoTyMRmqeLT\n"
						+ "DHV1LwJAW4xaV37Eo4z9B7Kr4Hzd1MA1ueW5QQDt+Q4vN/r7z4/1FHyFzh0Xcucd\n"
						+ "7nZX7qj0CkmgzOVG+Rb0P5LOxJA7gQJBAK1KQ2qNct375qPM9bEGSVGchH6k5X7+\n"
						+ "q4ztHdpFgTb/EzdbZiTG935GpjC1rwJuinTnrHOnkwv4j7iDRm24GF8CQQDqPvrQ\n"
						+ "GcItR6UUy0q/B8UxLzlE6t+HiznfiJKfyGgCHU56Y4/ZhzSQz2MZHz9SK4DsUL9s\n" + "bOYrWq8VY2fyjV1t\n"
						+ "-----END PRIVATE KEY-----");
	}

}
