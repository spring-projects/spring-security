/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.test.web.reactive.server;

import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.util.UriComponentsBuilder;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

/**
 * Contains Spring Security related request builders for
 * {@link WebTestClient}.
 *
 * @author Rob Winch
 * @since 7.1
 */
public final class SecurityMockServerRequestBuilders {

	private SecurityMockServerRequestBuilders() {
	}

	/**
	 * Creates a request that will submit a form based login to POST "/login".
	 * @return the {@link FormLoginRequestBuilder} for further customizations
	 */
	public static FormLoginRequestBuilder formLogin() {
		return new FormLoginRequestBuilder();
	}

	/**
	 * Creates a request that will submit a form based login to POST
	 * {@code loginProcessingUrl}.
	 * @param loginProcessingUrl the URL to POST to
	 * @return the {@link FormLoginRequestBuilder} for further customizations
	 */
	public static FormLoginRequestBuilder formLogin(String loginProcessingUrl) {
		return formLogin().loginProcessingUrl(loginProcessingUrl);
	}

	/**
	 * Creates a logout request.
	 * @return the {@link LogoutRequestBuilder} for additional customizations
	 */
	public static LogoutRequestBuilder logout() {
		return new LogoutRequestBuilder();
	}

	/**
	 * Creates a logout request to the specified {@code logoutUrl}.
	 * @param logoutUrl the logout request URL
	 * @return the {@link LogoutRequestBuilder} for additional customizations
	 */
	public static LogoutRequestBuilder logout(String logoutUrl) {
		return logout().logoutUrl(logoutUrl);
	}

	/**
	 * Creates a logout request.
	 *
	 * @author Rob Winch
	 * @since 7.1
	 */
	public static final class LogoutRequestBuilder {

		private String logoutUrl = "/logout";

		private LogoutRequestBuilder() {
		}

		/**
		 * Executes the logout request using the provided {@link WebTestClient}. This will
		 * automatically apply {@link SecurityMockServerConfigurers#csrf()}.
		 * @param webTestClient the {@link WebTestClient} to use
		 * @return the {@link WebTestClient.ResponseSpec}
		 */
		public WebTestClient.ResponseSpec exchange(WebTestClient webTestClient) {
			Assert.notNull(webTestClient, "webTestClient cannot be null");
			return webTestClient.mutateWith(csrf())
				.post()
				.uri(this.logoutUrl)
				.accept(MediaType.TEXT_HTML, MediaType.ALL)
				.exchange();
		}

		/**
		 * Specifies the logout URL to POST to. Defaults to "/logout".
		 * @param logoutUrl the logout URL to POST to
		 * @return the {@link LogoutRequestBuilder} for additional customizations
		 */
		public LogoutRequestBuilder logoutUrl(String logoutUrl) {
			this.logoutUrl = logoutUrl;
			return this;
		}

		/**
		 * Specifies the logout URL to POST to.
		 * @param logoutUrl the logout URL to POST to
		 * @param uriVars the URI variables
		 * @return the {@link LogoutRequestBuilder} for additional customizations
		 */
		public LogoutRequestBuilder logoutUrl(String logoutUrl, Object... uriVars) {
			this.logoutUrl = UriComponentsBuilder.fromPath(logoutUrl).buildAndExpand(uriVars).encode().toString();
			return this;
		}

	}

	/**
	 * Creates a form based login request.
	 *
	 * @author Rob Winch
	 * @since 7.1
	 */
	public static final class FormLoginRequestBuilder {

		private String usernameParam = "username";

		private String passwordParam = "password";

		private String username = "user";

		private String password = "password";

		private String loginProcessingUrl = "/login";

		private MediaType acceptMediaType = MediaType.APPLICATION_FORM_URLENCODED;

		private FormLoginRequestBuilder() {
		}

		/**
		 * Executes the form login request using the provided {@link WebTestClient}. This
		 * will automatically apply {@link SecurityMockServerConfigurers#csrf()}.
		 * @param webTestClient the {@link WebTestClient} to use
		 * @return the {@link WebTestClient.ResponseSpec}
		 */
		public WebTestClient.ResponseSpec exchange(WebTestClient webTestClient) {
			Assert.notNull(webTestClient, "webTestClient cannot be null");
			return webTestClient.mutateWith(csrf())
				.post()
				.uri(this.loginProcessingUrl)
				.accept(this.acceptMediaType)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.body(BodyInserters.fromFormData(this.usernameParam, this.username).with(this.passwordParam,
						this.password))
				.exchange();
		}

		/**
		 * Specifies the URL to POST to. Default is "/login".
		 * @param loginProcessingUrl the URL to POST to
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder loginProcessingUrl(String loginProcessingUrl) {
			this.loginProcessingUrl = loginProcessingUrl;
			return this;
		}

		/**
		 * Specifies the URL to POST to.
		 * @param loginProcessingUrl the URL to POST to
		 * @param uriVars the URI variables
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder loginProcessingUrl(String loginProcessingUrl, Object... uriVars) {
			this.loginProcessingUrl = UriComponentsBuilder.fromPath(loginProcessingUrl)
				.buildAndExpand(uriVars)
				.encode()
				.toString();
			return this;
		}

		/**
		 * The HTTP parameter to place the username. Default is "username".
		 * @param usernameParameter the HTTP parameter to place the username
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder userParameter(String usernameParameter) {
			this.usernameParam = usernameParameter;
			return this;
		}

		/**
		 * The HTTP parameter to place the password. Default is "password".
		 * @param passwordParameter the HTTP parameter to place the password
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder passwordParam(String passwordParameter) {
			this.passwordParam = passwordParameter;
			return this;
		}

		/**
		 * The value of the password parameter. Default is "password".
		 * @param password the value of the password parameter
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder password(String password) {
			this.password = password;
			return this;
		}

		/**
		 * The value of the username parameter. Default is "user".
		 * @param username the value of the username parameter
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder user(String username) {
			this.username = username;
			return this;
		}

		/**
		 * Specify both the password parameter name and the password.
		 * @param passwordParameter the HTTP parameter to place the password
		 * @param password the value of the password parameter
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder password(String passwordParameter, String password) {
			passwordParam(passwordParameter);
			this.password = password;
			return this;
		}

		/**
		 * Specify both the username parameter name and the username.
		 * @param usernameParameter the HTTP parameter to place the username
		 * @param username the value of the username parameter
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder user(String usernameParameter, String username) {
			userParameter(usernameParameter);
			this.username = username;
			return this;
		}

		/**
		 * Specifies the media type to set as the Accept header in the request.
		 * @param acceptMediaType the {@link MediaType} to set as the Accept header
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder acceptMediaType(MediaType acceptMediaType) {
			this.acceptMediaType = acceptMediaType;
			return this;
		}

	}

}
