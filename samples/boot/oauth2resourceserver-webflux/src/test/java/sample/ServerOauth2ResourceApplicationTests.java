/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

/**
 * @author Rob Winch
 * @since 5.1
 */
@SpringBootTest
@AutoConfigureWebTestClient
@RunWith(SpringJUnit4ClassRunner.class)
public class ServerOauth2ResourceApplicationTests {
	@Autowired
	private WebTestClient rest;

	@Test
	public void getWhenValidTokenThenIsOk() {
		String token = "eyJhbGciOiJSUzI1NiJ9.eyJzY29wZSI6Im1lc3NhZ2U6cmVhZCIsImV4cCI6MzEwNjMyODEzMSwianRpIjoiOGY5ZjFiYzItOWVlMi00NTJkLThhMGEtODg3YmE4YmViYjYzIn0.CM_KulSsIrNXW1x6NFeN5VwKQiIW-LIAScJzakRFDox8Ql7o4WOb0ubY3CjWYnglwqYzBvH9McCFqVrUtzdfODY5tyEEJSxWndIGExOi2osrwRPsY3AGzNa23GMfC9I03BFP1IFCq4ZfL-L6yVcIjLke-rA40UG-r-oA7r-N_zsLc5poO7Azf29IQgQF0GSRp4AKQprYHF5Q-Nz9XkILMDz9CwPQ9cbdLCC9smvaGmEAjMUr-C1QgM-_ulb42gWtRDLorW_eArg8g-fmIP0_w82eNWCBjLTy-WaDMACnDVrrUVsUMCqx6jS6h8_uejKly2NFuhyueIHZTTySqCZoTA";
		this.rest.get().uri("/")
				.headers(headers -> headers.setBearerAuth(token))
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("Hello, null!");
	}

	@Test
	public void getWhenNoTokenThenIsUnauthorized() {
		this.rest.get().uri("/")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
	}

	@Test
	public void getWhenNone() {
		String token = "ew0KICAiYWxnIjogIm5vbmUiLA0KICAidHlwIjogIkpXVCINCn0.ew0KICAic3ViIjogIjEyMzQ1Njc4OTAiLA0KICAibmFtZSI6ICJKb2huIERvZSIsDQogICJpYXQiOiAxNTE2MjM5MDIyDQp9.";
		this.rest.get().uri("/")
				.headers(headers -> headers.setBearerAuth(token))
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\", error_description=\"Unsupported algorithm of none\", error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"");
	}

	@Test
	public void getWhenInvalidToken() {
		String token = "a";
		this.rest.get().uri("/")
				.headers(headers -> headers.setBearerAuth(token))
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\", error_description=\"An error occurred while attempting to decode the Jwt: Invalid JWT serialization: Missing dot delimiter(s)\", error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"");
	}
}
