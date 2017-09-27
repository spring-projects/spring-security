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
package org.springframework.security.oauth2.client.registration;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.Set;

/**
 * A convenience class that provides a <i>&quot;flattened&quot;</i> property structure for {@link ClientRegistration}.
 *
 * <p>
 * This class may be used to <i>&quot;bind&quot;</i> property values located in the {@link org.springframework.core.env.Environment}
 * and then pass it to {@link ClientRegistration.Builder#Builder(ClientRegistrationProperties)}
 * to construct a {@link ClientRegistration} instance.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClientRegistration
 */
public class ClientRegistrationProperties {
	private String registrationId;
	private String clientId;
	private String clientSecret;
	private ClientAuthenticationMethod clientAuthenticationMethod = ClientAuthenticationMethod.BASIC;
	private AuthorizationGrantType authorizationGrantType;
	private String redirectUri;
	private Set<String> scope;
	private String authorizationUri;
	private String tokenUri;
	private String userInfoUri;
	private String userNameAttributeName;
	private String jwkSetUri;
	private String clientName;

	public String getRegistrationId() {
		return this.registrationId;
	}

	public void setRegistrationId(String registrationId) {
		this.registrationId = registrationId;
	}

	public String getClientId() {
		return this.clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return this.clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public ClientAuthenticationMethod getClientAuthenticationMethod() {
		return this.clientAuthenticationMethod;
	}

	public void setClientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
		this.clientAuthenticationMethod = clientAuthenticationMethod;
	}

	public AuthorizationGrantType getAuthorizationGrantType() {
		return this.authorizationGrantType;
	}

	public void setAuthorizationGrantType(AuthorizationGrantType authorizationGrantType) {
		this.authorizationGrantType = authorizationGrantType;
	}

	public String getRedirectUri() {
		return this.redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

	public Set<String> getScope() {
		return this.scope;
	}

	public void setScope(Set<String> scope) {
		this.scope = scope;
	}

	public String getAuthorizationUri() {
		return this.authorizationUri;
	}

	public void setAuthorizationUri(String authorizationUri) {
		this.authorizationUri = authorizationUri;
	}

	public String getTokenUri() {
		return this.tokenUri;
	}

	public void setTokenUri(String tokenUri) {
		this.tokenUri = tokenUri;
	}

	public String getUserInfoUri() {
		return this.userInfoUri;
	}

	public void setUserInfoUri(String userInfoUri) {
		this.userInfoUri = userInfoUri;
	}

	public String getUserNameAttributeName() {
		return this.userNameAttributeName;
	}

	public void setUserNameAttributeName(String userNameAttributeName) {
		this.userNameAttributeName = userNameAttributeName;
	}

	public String getJwkSetUri() {
		return this.jwkSetUri;
	}

	public void setJwkSetUri(String jwkSetUri) {
		this.jwkSetUri = jwkSetUri;
	}

	public String getClientName() {
		return this.clientName;
	}

	public void setClientName(String clientName) {
		this.clientName = clientName;
	}
}
