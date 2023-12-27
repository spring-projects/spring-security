/*
 * Copyright 2013-2024 the original author or authors.
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

package org.springframework.security.crypto.encrypt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Dave Syer
 *
 */
public class RsaRawEncryptorTests {

	private RsaRawEncryptor encryptor = new RsaRawEncryptor();

	@BeforeEach
	public void init() {
		LONG_STRING = SHORT_STRING + SHORT_STRING + SHORT_STRING + SHORT_STRING;
		for (int i = 0; i < 4; i++) {
			LONG_STRING = LONG_STRING + LONG_STRING;
		}
	}

	@Test
	public void roundTrip() {
		assertThat(this.encryptor.decrypt(this.encryptor.encrypt("encryptor"))).isEqualTo("encryptor");
	}

	@Test
	public void roundTripOeap() {
		this.encryptor = new RsaRawEncryptor(RsaAlgorithm.OAEP);
		assertThat(this.encryptor.decrypt(this.encryptor.encrypt("encryptor"))).isEqualTo("encryptor");
	}

	@Test
	public void roundTripLongString() {
		assertThat(this.encryptor.decrypt(this.encryptor.encrypt(LONG_STRING))).isEqualTo(LONG_STRING);
	}

	@Test
	public void roundTripLongStringOeap() {
		this.encryptor = new RsaRawEncryptor(RsaAlgorithm.OAEP);
		assertThat(this.encryptor.decrypt(this.encryptor.encrypt(LONG_STRING))).isEqualTo(LONG_STRING);
	}

	@Test
	public void roundTrip2048Key() {
		String pemData = "-----BEGIN RSA PRIVATE KEY-----"
				+ "MIIEpQIBAAKCAQEA5KHEkCudAHCKIUHKyW6Z8dMyQsKrLbpDe0wDzx9MBARcOoS9"
				+ "ZUjzXwK6p/0RM6aCp+b9kkr37QKQ9K/Am13sr0z8Mkn1Q2cvXiL5gbnY1nYGk8/m"
				+ "CBX3QEhH2UII4yJsDVx1xmcSorZaWmeNKor7Zl3SZaQpWTvlkMgQKwY8DZL6PPxt"
				+ "JRPeKmuUY6B59u5okh1G6Y9OnT2dVxAkqT8WgLHu6StxBmueJ272x2sUWUzoDhnP"
				+ "7JRqa7h7t6fml3o3Op1iCywCOFzCIcK6G/oG/WZ7tbBYkwQdDjn/9VMdKkkPufwq"
				+ "zt4S75NJygXDwDnNPiTVoaOwrRrL8ahgw6bFCQIDAQABAoIBAECIMHUI+l2fZj2Q"
				+ "1m4Ym7cYB320eKCFjHqGsCSMDuarXGTgBp1KA/dzS8ASvAI6I3LEzhm2s1fge420"
				+ "9cZksmOgdSa0nVeTDlmhwY8OJ9gQpDagXas2l/066Zy2+M8zbhAvYsbHXQk0MziF"
				+ "NeEmLWNtY+9wcINRVrCQ549dSSIDK6UX21oU6d1mrlnF5/bbbdDIM3dKok355jwx"
				+ "0HFY0tJIs1zArsBVoz3Ccu1MQEfnxEFM1LLPi5rE6cuHIOBinbD1OQ2R/HM2aukG"
				+ "Rk2m6F3wAieJ7zpt5yaHuuIedn8p8m2NVulXAjgkY2oQl3GGiDH/H7eZlrvQRg6E"
				+ "D8Bq+ykCgYEA+AfPXVeeVg3Qu0KsNrACek/o92BMY9g3GyPVGULGvq9seoNB86hj"
				+ "nXasqngBfTlOfJFiahoEzRBB9hIyo1zMw4x99pR8nGxhR3aU+v8EGftMABGHWsB9"
				+ "Jxj4YQH4fhi57iBa72QmNPbu/1o7y3SEe68E5PJ8KY3jc4xos8Vl658CgYEA6/pk"
				+ "t6WZII+9lpxQfePQDIlBWAphiQceh995bGXfDmX3vOVmPozix9/fUtF1TeKS/ypw"
				+ "u++Qmvj5oMsBVrjCyoOYfHKE2vGrLoEzkX/sPO65IsV00geZZoyCEKEE3USJfY46"
				+ "u0hs61oP8HJyLhLiYiGcFTzZ4nEvvEbiM4E/DlcCgYEA6S0OecZhiK08SpAHrvIR"
				+ "okN11PqnVkZyqAUr1a+9gI8TAKpdWmA4JlTnRuvDGqLBcsKLLwx+7voVyOyaxpH7"
				+ "vutZkHNQIw6Q9co5jS4qAPMLJBVWlq7X+eWzvB9KKeG9Cm1IkD4q3Sg4z79Y75D+"
				+ "6/hCNarxp29JIdwior81bikCgYEApp1P+b7pxGzZPvs1df2hCwjqY0BJJ5goPWVT"
				+ "dW7kNGVYqz4JmAafpOJz6yTLP2fHxHRxzrBSmKlMj/RmCJZBqv2Jb+zn0zMpW5eM"
				+ "EqKQ6WDgxSVH23fUHuz8dMNMDPL0ZPtEirGTfgVEFdCov9FDmGgErZYefVzPiI8/"
				+ "7X/HRtcCgYEApQ2YS+0DLPqaM0cC6/6hDr/jmHLFhHaV6DZR7M9HHDnMN2uMlOEa"
				+ "RYvXRMBjyQ7LQkwOj6K5k8MVrsDDM5dbekTBgcJMHfM9uViDkB0VPYULORmDJ20N"
				+ "MLowIAiSon2B2/isatY80YtFq+bRyvPOzjGvinHN3MU1GH/gFuS0fiw=" + "-----END RSA PRIVATE KEY-----";
		RsaRawEncryptor encryptor_2048 = new RsaRawEncryptor(pemData);
		assertThat(encryptor_2048.decrypt(encryptor_2048.encrypt("encryptor"))).isEqualTo("encryptor");
	}

	@Test
	public void roundTrip4096Key() {
		String pemData = "-----BEGIN RSA PRIVATE KEY-----"
				+ "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" + "-----END RSA PRIVATE KEY-----";
		RsaRawEncryptor encryptor_4096 = new RsaRawEncryptor(pemData);
		assertThat(encryptor_4096.decrypt(encryptor_4096.encrypt("encryptor"))).isEqualTo("encryptor");
	}

	private static final String SHORT_STRING = "Bacon ipsum dolor sit amet tail pork loin pork chop filet mignon flank fatback tenderloin boudin shankle corned beef t-bone short ribs. Meatball capicola ball tip short loin beef ribs shoulder, kielbasa pork chop meatloaf biltong porchetta bresaola t-bone spare ribs. Andouille t-bone sausage ground round frankfurter venison. Ground round meatball chicken ribeye doner tongue porchetta.";

	private static String LONG_STRING;

}
