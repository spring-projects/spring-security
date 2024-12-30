/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.authentication.password;

import java.io.IOException;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;

class HaveIBeenPwnedRestApiReactivePasswordCheckerTests {

	private final String pwnedPasswords = """
			2CDE4CDCFA5AD7D223BD1800338FBEAA04E:1
			2CF90F92EE1941547BB13DFC7D0E0AFE504:1
			2D10A6654B6D75908AE572559542245CBFA:6
			2D4FCF535FE92B8B950424E16E65EFBFED3:1
			2D6980B9098804E7A83DC5831BFBAF3927F:1
			2D8D1B3FAACCA6A3C6A91617B2FA32E2F57:1
			2DC183F740EE76F27B78EB39C8AD972A757:300185
			2DE4C0087846D223DBBCCF071614590F300:3
			2DEA2B1D02714099E4B7A874B4364D518F6:1
			2E750AE8C4756A20CE040BF3DDF094FA7EC:1
			2E90B7B3C5C1181D16C48E273D9AC7F3C16:5
			2E991A9162F24F01826D8AF73CA20F2B430:1
			2EAE5EA981BFAF29A8869A40BDDADF3879B:2
			2F1AC09E3846595E436BBDDDD2189358AF9:1
			""";

	private final MockWebServer server = new MockWebServer();

	private final HaveIBeenPwnedRestApiReactivePasswordChecker passwordChecker = new HaveIBeenPwnedRestApiReactivePasswordChecker();

	@BeforeEach
	void setup() throws IOException {
		this.server.start();
		HttpUrl url = this.server.url("/range/");
		this.passwordChecker.setWebClient(WebClient.builder().baseUrl(url.toString()).build());
	}

	@AfterEach
	void tearDown() throws IOException {
		this.server.shutdown();
	}

	@Test
	void checkWhenPasswordIsLeakedThenIsCompromised() throws InterruptedException {
		this.server.enqueue(new MockResponse().setBody(this.pwnedPasswords).setResponseCode(200));
		StepVerifier.create(this.passwordChecker.check("P@ssw0rd"))
			.assertNext((check) -> assertThat(check.isCompromised()).isTrue())
			.verifyComplete();
		assertThat(this.server.takeRequest().getPath()).isEqualTo("/range/21BD1");
	}

	@Test
	void checkWhenPasswordNotLeakedThenNotCompromised() {
		this.server.enqueue(new MockResponse().setBody(this.pwnedPasswords).setResponseCode(200));
		StepVerifier.create(this.passwordChecker.check("My1nCr3d!bL3P@SS0W0RD"))
			.assertNext((check) -> assertThat(check.isCompromised()).isFalse())
			.verifyComplete();
	}

	@Test
	void checkWhenNoPasswordsReturnedFromApiCallThenNotCompromised() {
		this.server.enqueue(new MockResponse().setResponseCode(200));
		StepVerifier.create(this.passwordChecker.check("P@ssw0rd"))
			.assertNext((check) -> assertThat(check.isCompromised()).isFalse())
			.verifyComplete();
	}

	@Test
	void checkWhenResponseStatusNot200ThenNotCompromised() {
		this.server.enqueue(new MockResponse().setResponseCode(503));
		StepVerifier.create(this.passwordChecker.check("123456"))
			.assertNext((check) -> assertThat(check.isCompromised()).isFalse())
			.verifyComplete();
		this.server.enqueue(new MockResponse().setResponseCode(404));
		StepVerifier.create(this.passwordChecker.check("123456"))
			.assertNext((check) -> assertThat(check.isCompromised()).isFalse())
			.verifyComplete();
	}

}
