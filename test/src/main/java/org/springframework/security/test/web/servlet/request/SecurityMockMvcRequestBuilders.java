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

package org.springframework.security.test.web.servlet.request;

import jakarta.servlet.ServletContext;
import org.jspecify.annotations.Nullable;

import org.springframework.beans.Mergeable;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.util.UriComponentsBuilder;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Contains Spring Security related {@link MockMvc} {@link RequestBuilder}s.
 *
 * @author Rob Winch
 * @since 4.0
 */
public final class SecurityMockMvcRequestBuilders {

	private SecurityMockMvcRequestBuilders() {
	}

	/**
	 * Creates a request (including any necessary {@link CsrfToken}) that will submit a
	 * form based login to POST "/login".
	 * @return the FormLoginRequestBuilder for further customizations
	 */
	public static FormLoginRequestBuilder formLogin() {
		return new FormLoginRequestBuilder();
	}

	/**
	 * Creates a request (including any necessary {@link CsrfToken}) that will submit a
	 * form based login to POST {@code loginProcessingUrl}.
	 * @param loginProcessingUrl the URL to POST to
	 * @return the FormLoginRequestBuilder for further customizations
	 */
	public static FormLoginRequestBuilder formLogin(String loginProcessingUrl) {
		return formLogin().loginProcessingUrl(loginProcessingUrl);
	}

	/**
	 * Creates a logout request.
	 * @return the LogoutRequestBuilder for additional customizations
	 */
	public static LogoutRequestBuilder logout() {
		return new LogoutRequestBuilder();
	}

	/**
	 * Creates a logout request (including any necessary {@link CsrfToken}) to the
	 * specified {@code logoutUrl}
	 * @param logoutUrl the logout request URL
	 * @return the LogoutRequestBuilder for additional customizations
	 */
	public static LogoutRequestBuilder logout(String logoutUrl) {
		return new LogoutRequestBuilder().logoutUrl(logoutUrl);
	}

	/**
	 * Creates a logout request (including any necessary {@link CsrfToken})
	 *
	 * @author Rob Winch
	 * @since 4.0
	 */
	public static final class LogoutRequestBuilder implements RequestBuilder, Mergeable {

		private String logoutUrl = "/logout";

		private RequestPostProcessor postProcessor = csrf();

		private @Nullable Mergeable parent;

		private LogoutRequestBuilder() {
		}

		@Override
		public MockHttpServletRequest buildRequest(ServletContext servletContext) {
			MockHttpServletRequestBuilder logoutRequest = post(this.logoutUrl).accept(MediaType.TEXT_HTML,
					MediaType.ALL);
			if (this.parent != null) {
				logoutRequest = (MockHttpServletRequestBuilder) logoutRequest.merge(this.parent);
			}
			MockHttpServletRequest request = logoutRequest.buildRequest(servletContext);
			logoutRequest.postProcessRequest(request);
			return this.postProcessor.postProcessRequest(request);
		}

		/**
		 * Specifies the logout URL to POST to. Defaults to "/logout".
		 * @param logoutUrl the logout URL to POST to. Defaults to "/logout".
		 * @return the {@link LogoutRequestBuilder} for additional customizations
		 */
		public LogoutRequestBuilder logoutUrl(String logoutUrl) {
			this.logoutUrl = logoutUrl;
			return this;
		}

		/**
		 * Specifies the logout URL to POST to.
		 * @param logoutUrl the logout URL to POST to.
		 * @param uriVars the URI variables
		 * @return the {@link LogoutRequestBuilder} for additional customizations
		 */
		public LogoutRequestBuilder logoutUrl(String logoutUrl, Object... uriVars) {
			this.logoutUrl = UriComponentsBuilder.fromPath(logoutUrl).buildAndExpand(uriVars).encode().toString();
			return this;
		}

		@Override
		public boolean isMergeEnabled() {
			return true;
		}

		@Override
		public Object merge(@Nullable Object parent) {
			if (parent == null) {
				return this;
			}
			if (parent instanceof Mergeable) {
				this.parent = (Mergeable) parent;
				return this;
			}
			throw new IllegalArgumentException("Cannot merge with [" + parent.getClass().getName() + "]");
		}

	}

	/**
	 * Creates a form based login request including any necessary {@link CsrfToken}.
	 *
	 * @author Rob Winch
	 * @since 4.0
	 */
	public static final class FormLoginRequestBuilder implements RequestBuilder, Mergeable {

		private String usernameParam = "username";

		private String passwordParam = "password";

		private String username = "user";

		private String password = "password";

		private String loginProcessingUrl = "/login";

		private MediaType acceptMediaType = MediaType.APPLICATION_FORM_URLENCODED;

		private @Nullable Mergeable parent;

		private RequestPostProcessor postProcessor = csrf();

		private FormLoginRequestBuilder() {
		}

		@Override
		public MockHttpServletRequest buildRequest(ServletContext servletContext) {
			MockHttpServletRequestBuilder loginRequest = post(this.loginProcessingUrl).accept(this.acceptMediaType)
				.param(this.usernameParam, this.username)
				.param(this.passwordParam, this.password);
			if (this.parent != null) {
				loginRequest = (MockHttpServletRequestBuilder) loginRequest.merge(this.parent);
			}
			MockHttpServletRequest request = loginRequest.buildRequest(servletContext);
			loginRequest.postProcessRequest(request);
			return this.postProcessor.postProcessRequest(request);
		}

		/**
		 * Specifies the URL to POST to. Default is "/login"
		 * @param loginProcessingUrl the URL to POST to. Default is "/login"
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
		 * @param usernameParameter the HTTP parameter to place the username. Default is
		 * "username".
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder userParameter(String usernameParameter) {
			this.usernameParam = usernameParameter;
			return this;
		}

		/**
		 * The HTTP parameter to place the password. Default is "password".
		 * @param passwordParameter the HTTP parameter to place the password. Default is
		 * "password".
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder passwordParam(String passwordParameter) {
			this.passwordParam = passwordParameter;
			return this;
		}

		/**
		 * The value of the password parameter. Default is "password".
		 * @param password the value of the password parameter. Default is "password".
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder password(String password) {
			this.password = password;
			return this;
		}

		/**
		 * The value of the username parameter. Default is "user".
		 * @param username the value of the username parameter. Default is "user".
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder user(String username) {
			this.username = username;
			return this;
		}

		/**
		 * Specify both the password parameter name and the password.
		 * @param passwordParameter the HTTP parameter to place the password. Default is
		 * "password".
		 * @param password the value of the password parameter. Default is "password".
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder password(String passwordParameter, String password) {
			passwordParam(passwordParameter);
			this.password = password;
			return this;
		}

		/**
		 * Specify both the password parameter name and the password.
		 * @param usernameParameter the HTTP parameter to place the username. Default is
		 * "username".
		 * @param username the value of the username parameter. Default is "user".
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder user(String usernameParameter, String username) {
			userParameter(usernameParameter);
			this.username = username;
			return this;
		}

		/**
		 * Specify a media type to set as the Accept header in the request.
		 * @param acceptMediaType the {@link MediaType} to set the Accept header to.
		 * Default is: MediaType.APPLICATION_FORM_URLENCODED
		 * @return the {@link FormLoginRequestBuilder} for additional customizations
		 */
		public FormLoginRequestBuilder acceptMediaType(MediaType acceptMediaType) {
			this.acceptMediaType = acceptMediaType;
			return this;
		}

		@Override
		public boolean isMergeEnabled() {
			return true;
		}

		@Override
		public Object merge(@Nullable Object parent) {
			if (parent == null) {
				return this;
			}
			if (parent instanceof Mergeable) {
				this.parent = (Mergeable) parent;
				return this;
			}
			throw new IllegalArgumentException("Cannot merge with [" + parent.getClass().getName() + "]");
		}

	}

}
