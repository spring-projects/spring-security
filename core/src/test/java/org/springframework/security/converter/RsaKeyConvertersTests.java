/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.converter;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.assertj.core.api.Assertions;
import org.junit.Test;

import org.springframework.core.convert.converter.Converter;

import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Tests for {@link RsaKeyConverters}
 */
public class RsaKeyConvertersTests {

	private static final String PKCS8_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n"
			+ "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCMk7CKSTfu3QoV\n"
			+ "HoPVXxwZO+qweztd36cVWYqGOZinrOR2crWFu50AgR2CsdIH0+cqo7F4Vx7/3O8i\n"
			+ "RpYYZPe2VoO5sumzJt8P6fS80/TAKjhJDAqgZKRJTgGN8KxCM6p/aJli1ZeDBqiV\n"
			+ "v7vJJe+ZgJuPGRS+HMNa/wPxEkqqXsglcJcQV1ZEtfKXSHB7jizKpRL38185SyAC\n"
			+ "pwyjvBu6Cmm1URfhQo88mf239ONh4dZ2HoDfzN1q6Ssu4F4hgutxr9B0DVLDP5u+\n"
			+ "WFrm3nsJ76zf99uJ+ntMUHJ+bY+gOjSlVWIVBIZeAaEGKCNWRk/knjvjbijpvm3U\n"
			+ "acGlgdL3AgMBAAECggEACxxxS7zVyu91qI2s5eSKmAQAXMqgup6+2hUluc47nqUv\n"
			+ "uZz/c/6MPkn2Ryo+65d4IgqmMFjSfm68B/2ER5FTcvoLl1Xo2twrrVpUmcg3BClS\n"
			+ "IZPuExdhVNnxjYKEWwcyZrehyAoR261fDdcFxLRW588efIUC+rPTTRHzAc7sT+Ln\n"
			+ "t/uFeYNWJm3LaegOLoOmlMAhJ5puAWSN1F0FxtRf/RVgzbLA9QC975SKHJsfWCSr\n"
			+ "IZyPsdeaqomKaF65l8nfqlE0Ua2L35gIOGKjUwb7uUE8nI362RWMtYdoi3zDDyoY\n"
			+ "hSFbgjylCHDM0u6iSh6KfqOHtkYyJ8tUYgVWl787wQKBgQDYO3wL7xuDdD101Lyl\n"
			+ "AnaDdFB9fxp83FG1cWr+t7LYm9YxGfEUsKHAJXN6TIayDkOOoVwIl+Gz0T3Z06Bm\n"
			+ "eBGLrB9mrVA7+C7NJwu5gTMlzP6HxUR9zKJIQ/VB1NUGM77LSmvOFbHc9Q0+z8EH\n"
			+ "X5WO516a3Z7lNtZJcCoPOtu2rwKBgQCmbj41Fh+SSEUApCEKms5ETRpe7LXQlJgx\n"
			+ "yW7zcJNNuIb1C3vBLPxjiOTMgYKOeMg5rtHTGLT43URHLh9ArjawasjSAr4AM3J4\n"
			+ "xpoi/sKGDdiKOsuDWIGfzdYL8qyTHSdpZLQsCTMRiRYgAHZFPgNa7SLZRfZicGlr\n"
			+ "GHN1rJW6OQKBgEjiM/upyrJSWeypUDSmUeAZMpA6aWkwsfHgmtnkfUn5rQa74cDB\n"
			+ "kKO9e+D7LmOR3z+SL/1NhGwh2SE07dncGr3jdGodfO/ZxZyszozmeaECKcEFwwJM\n"
			+ "GV8WWPKplGwUwPiwywmZ0mvRxXcoe73KgBS88+xrSwWjqDL0tZiQlEJNAoGATkei\n"
			+ "GMQMG3jEg9Wu+NbxV6zQT3+U0MNjhl9RQU1c63x0dcNt9OFc4NAdlZcAulRTENaK\n"
			+ "OHjxffBM0hH+fySx8m53gFfr2BpaqDX5f6ZGBlly1SlsWZ4CchCVsc71nshipi7I\n"
			+ "k8HL9F5/OpQdDNprJ5RMBNfkWE65Nrcsb1e6oPkCgYAxwgdiSOtNg8PjDVDmAhwT\n"
			+ "Mxj0Dtwi2fAqQ76RVrrXpNp3uCOIAu4CfruIb5llcJ3uak0ZbnWri32AxSgk80y3\n"
			+ "EWiRX/WEDu5znejF+5O3pI02atWWcnxifEKGGlxwkcMbQdA67MlrJLFaSnnGpNXo\n" + "yPfcul058SOqhafIZQMEKQ==\n"
			+ "-----END PRIVATE KEY-----";

	private static final String PKCS1_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n"
			+ "MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw\n"
			+ "33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW\n"
			+ "+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB\n"
			+ "AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS\n"
			+ "3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp\n"
			+ "uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE\n"
			+ "2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0\n"
			+ "GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K\n"
			+ "Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY\n"
			+ "6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5\n"
			+ "fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523\n"
			+ "Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP\n"
			+ "FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==\n" + "-----END RSA PRIVATE KEY-----";

	private static final String X509_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
			+ "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd\n"
			+ "UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs\n"
			+ "HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D\n" + "o2kQ+X5xK9cipRgEKwIDAQAB\n"
			+ "-----END PUBLIC KEY-----";

	private static final String MALFORMED_X509_KEY = "malformed";

	private final Converter<InputStream, RSAPublicKey> x509 = RsaKeyConverters.x509();

	private final Converter<InputStream, RSAPrivateKey> pkcs8 = RsaKeyConverters.pkcs8();

	@Test
	public void pkcs8WhenConvertingPkcs8PrivateKeyThenOk() {
		RSAPrivateKey key = this.pkcs8.convert(toInputStream(PKCS8_PRIVATE_KEY));
		Assertions.assertThat(key).isInstanceOf(RSAPrivateCrtKey.class);
		Assertions.assertThat(key.getModulus().bitLength()).isEqualTo(2048);
	}

	@Test
	public void pkcs8WhenConvertingPkcs1PrivateKeyThenIllegalArgumentException() {
		assertThatCode(() -> this.pkcs8.convert(toInputStream(PKCS1_PRIVATE_KEY)))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void x509WhenConverteringX509PublicKeyThenOk() {
		RSAPublicKey key = this.x509.convert(toInputStream(X509_PUBLIC_KEY));
		Assertions.assertThat(key.getModulus().bitLength()).isEqualTo(1024);
	}

	@Test
	public void x509WhenConvertingDerEncodedX509PublicKeyThenIllegalArgumentException() {
		assertThatCode(() -> this.x509.convert(toInputStream(MALFORMED_X509_KEY)))
				.isInstanceOf(IllegalArgumentException.class);
	}

	private static InputStream toInputStream(String string) {
		return new ByteArrayInputStream(string.getBytes(StandardCharsets.UTF_8));
	}

}
