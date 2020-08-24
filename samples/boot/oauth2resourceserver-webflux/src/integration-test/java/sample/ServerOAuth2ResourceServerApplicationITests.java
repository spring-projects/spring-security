/*
 * Copyright 2002-2018 the original author or authors.
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

package sample;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.function.Consumer;

import static org.hamcrest.Matchers.containsString;

/**
 * @author Rob Winch
 * @since 5.1
 */
@SpringBootTest
@AutoConfigureWebTestClient
@RunWith(SpringJUnit4ClassRunner.class)
public class ServerOAuth2ResourceServerApplicationITests {

	Consumer<HttpHeaders> noScopesToken = (http) -> http.setBearerAuth("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0IiwiZXhwIjo0NjgzODA1MTI4fQ.ULEPdHG-MK5GlrTQMhgqcyug2brTIZaJIrahUeq9zaiwUSdW83fJ7W1IDd2Z3n4a25JY2uhEcoV95lMfccHR6y_2DLrNvfta22SumY9PEDF2pido54LXG6edIGgarnUbJdR4rpRe_5oRGVa8gDx8FnuZsNv6StSZHAzw5OsuevSTJ1UbJm4UfX3wiahFOQ2OI6G-r5TB2rQNdiPHuNyzG5yznUqRIZ7-GCoMqHMaC-1epKxiX8gYXRROuUYTtcMNa86wh7OVDmvwVmFioRcR58UWBRoO1XQexTtOQq_t8KYsrPZhb9gkyW8x2bAQF-d0J0EJY8JslaH6n4RBaZISww");
	Consumer<HttpHeaders> messageReadToken = (http) -> http.setBearerAuth("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0Iiwic2NvcGUiOiJtZXNzYWdlOnJlYWQiLCJleHAiOjQ2ODM4MDUxNDF9.h-j6FKRFdnTdmAueTZCdep45e6DPwqM68ZQ8doIJ1exi9YxAlbWzOwId6Bd0L5YmCmp63gGQgsBUBLzwnZQ8kLUgUOBEC3UzSWGRqMskCY9_k9pX0iomX6IfF3N0PaYs0WPC4hO1s8wfZQ-6hKQ4KigFi13G9LMLdH58PRMK0pKEvs3gCbHJuEPw-K5ORlpdnleUTQIwINafU57cmK3KocTeknPAM_L716sCuSYGvDl6xUTXO7oPdrXhS_EhxLP6KxrpI1uD4Ea_5OWTh7S0Wx5LLDfU6wBG1DowN20d374zepOIEkR-Jnmr_QlR44vmRqS5ncrF-1R0EGcPX49U6A");

	@Autowired
	private WebTestClient rest;


	@Test
	public void getWhenValidBearerTokenThenAllows() {

		this.rest.get().uri("/")
				.headers(this.noScopesToken)
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("Hello, subject!");
	}

	@Test
	public void getWhenValidBearerTokenThenScopedRequestsAlsoWork() {

		this.rest.get().uri("/message")
				.headers(this.messageReadToken)
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("secret message");
	}

	@Test
	public void getWhenInsufficientlyScopedBearerTokenThenDeniesScopedMethodAccess() {

		this.rest.get().uri("/message")
				.headers(this.noScopesToken)
				.exchange()
				.expectStatus().isForbidden()
				.expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, containsString("Bearer error=\"insufficient_scope\""));
	}
}
