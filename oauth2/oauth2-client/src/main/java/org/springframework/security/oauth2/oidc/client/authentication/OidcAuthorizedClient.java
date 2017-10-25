/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.oidc.client.authentication;

import org.springframework.security.oauth2.client.authentication.AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.oidc.core.IdToken;
import org.springframework.util.Assert;

/**
 * A representation of an OpenID Connect 1.0 <i>&quot;Authorized Client&quot;</i>.
 * <p>
 * A client is considered <i>&quot;authorized&quot;</i>
 * when it receives a successful response from the <i>Token Endpoint</i>.
 * <p>
 * This class associates the {@link #getClientRegistration() Client}
 * to the {@link #getAccessToken() Access Token}
 * granted/authorized by the {@link #getPrincipalName() Resource Owner}, along with
 * the {@link #getIdToken() ID Token} which contains Claims about the authentication of the End-User.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see IdToken
 * @see AuthorizedClient
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">3.1.3.3 Successful Token Response</a>
 */
public class OidcAuthorizedClient extends AuthorizedClient {
	private final IdToken idToken;

	public OidcAuthorizedClient(ClientRegistration clientRegistration, String principalName,
								AccessToken accessToken, IdToken idToken) {

		super(clientRegistration, principalName, accessToken);
		Assert.notNull(idToken, "idToken cannot be null");
		this.idToken = idToken;
	}

	public IdToken getIdToken() {
		return this.idToken;
	}
}
