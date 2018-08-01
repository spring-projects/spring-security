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
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Integration tests for the OAuth 2.0 client filters {@link OAuth2AuthorizationRequestRedirectFilter}
 * and {@link OAuth2AuthorizationCodeGrantFilter}. These filters work together to realize
 * the OAuth 2.0 Authorization Code Grant flow.
 *
 * @author Joe Grandja
 * @since 5.1
 */
@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureWebTestClient
@RunWith(SpringRunner.class)
public class OAuth2AuthorizationCodeGrantApplicationTests {
	@Autowired
	private WebTestClient rest;

	@Test
	@WithMockUser
	public void requestWhenClientNotAuthorizedThenRedirectForAuthorization() throws Exception {
		this.rest.get()
			.uri("http://localhost/repos")
			.exchange()
			.expectStatus().is3xxRedirection()
			.expectHeader().valueMatches(HttpHeaders.LOCATION, "https://github.com/login/oauth/authorize\\?response_type=code&client_id=client-id&scope=public_repo&state=.{15,}&redirect_uri=http%3A%2F%2Flocalhost%2Fauthorize%2Foauth2%2Fcode%2Fgithub");
	}

}
