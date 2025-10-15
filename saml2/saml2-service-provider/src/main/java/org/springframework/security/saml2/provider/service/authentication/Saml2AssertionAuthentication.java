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

package org.springframework.security.saml2.provider.service.authentication;

import java.io.Serial;
import java.util.Collection;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.BuildableAuthentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;

/**
 * An authentication based off of a SAML 2.0 Assertion
 *
 * @author Josh Cummings
 * @since 7.0
 * @see Saml2ResponseAssertionAccessor
 * @see Saml2ResponseAssertion
 */
public class Saml2AssertionAuthentication extends Saml2Authentication implements BuildableAuthentication {

	@Serial
	private static final long serialVersionUID = -4194323643788693205L;

	private final Saml2ResponseAssertionAccessor assertion;

	private final String relyingPartyRegistrationId;

	public Saml2AssertionAuthentication(Saml2ResponseAssertionAccessor assertion,
			Collection<? extends GrantedAuthority> authorities, String relyingPartyRegistrationId) {
		super(assertion, assertion.getResponseValue(), authorities);
		this.assertion = assertion;
		this.relyingPartyRegistrationId = relyingPartyRegistrationId;
	}

	public Saml2AssertionAuthentication(Object principal, Saml2ResponseAssertionAccessor assertion,
			Collection<? extends GrantedAuthority> authorities, String relyingPartyRegistrationId) {
		super(principal, assertion.getResponseValue(), authorities);
		this.assertion = assertion;
		this.relyingPartyRegistrationId = relyingPartyRegistrationId;
		setAuthenticated(true);
	}

	protected Saml2AssertionAuthentication(Builder<?> builder) {
		super(builder);
		this.assertion = builder.assertion;
		this.relyingPartyRegistrationId = builder.relyingPartyRegistrationId;
	}

	@Override
	public Saml2ResponseAssertionAccessor getCredentials() {
		return this.assertion;
	}

	public String getRelyingPartyRegistrationId() {
		return this.relyingPartyRegistrationId;
	}

	@Override
	public Builder<?> toBuilder() {
		return new Builder<>(this);
	}

	/**
	 * A builder of {@link Saml2AssertionAuthentication} instances
	 *
	 * @since 7.0
	 */
	public static class Builder<B extends Builder<B>> extends Saml2Authentication.Builder<B> {

		private Saml2ResponseAssertionAccessor assertion;

		private String relyingPartyRegistrationId;

		protected Builder(Saml2AssertionAuthentication token) {
			super(token);
			this.assertion = token.assertion;
			this.relyingPartyRegistrationId = token.relyingPartyRegistrationId;
		}

		/**
		 * Use these credentials. They must be of type
		 * {@link Saml2ResponseAssertionAccessor}.
		 * @param credentials the credentials to use
		 * @return the {@link Builder} for further configurations
		 */
		@Override
		public B credentials(@Nullable Object credentials) {
			Assert.isInstanceOf(Saml2ResponseAssertionAccessor.class, credentials,
					"credentials must be of type Saml2ResponseAssertionAccessor");
			saml2Response(((Saml2ResponseAssertionAccessor) credentials).getResponseValue());
			this.assertion = (Saml2ResponseAssertionAccessor) credentials;
			return (B) this;
		}

		/**
		 * Use this registration id
		 * @param relyingPartyRegistrationId the
		 * {@link RelyingPartyRegistration#getRegistrationId} to use
		 * @return the {@link Builder} for further configurations
		 */
		public B relyingPartyRegistrationId(String relyingPartyRegistrationId) {
			this.relyingPartyRegistrationId = relyingPartyRegistrationId;
			return (B) this;
		}

		@Override
		public Saml2AssertionAuthentication build() {
			return new Saml2AssertionAuthentication(this);
		}

	}

}
