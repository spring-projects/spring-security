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

package org.springframework.security.web.webauthn.authentication;

import java.io.Serial;
import java.util.Collection;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.util.Assert;

/**
 * A {@link WebAuthnAuthentication} is used to represent successful authentication with
 * WebAuthn.
 *
 * @author Rob Winch
 * @since 6.4
 * @see WebAuthnAuthenticationRequestToken
 */
public class WebAuthnAuthentication extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = -4879907158750659197L;

	private final PublicKeyCredentialUserEntity principal;

	public WebAuthnAuthentication(PublicKeyCredentialUserEntity principal,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		super.setAuthenticated(true);
	}

	private WebAuthnAuthentication(Builder<?> builder) {
		super(builder);
		this.principal = builder.principal;
	}

	@Override
	public void setAuthenticated(boolean authenticated) {
		Assert.isTrue(!authenticated, "Cannot set this token to trusted");
		super.setAuthenticated(authenticated);
	}

	@Override
	public @Nullable Object getCredentials() {
		return null;
	}

	@Override
	public PublicKeyCredentialUserEntity getPrincipal() {
		return this.principal;
	}

	@Override
	public String getName() {
		return this.principal.getName();
	}

	@Override
	public Builder<?> toBuilder() {
		return new Builder<>(this);
	}

	/**
	 * A builder of {@link WebAuthnAuthentication} instances
	 *
	 * @since 7.0
	 */
	public static final class Builder<B extends Builder<B>> extends AbstractAuthenticationBuilder<B> {

		private PublicKeyCredentialUserEntity principal;

		private Builder(WebAuthnAuthentication token) {
			super(token);
			this.principal = token.principal;
		}

		/**
		 * Use this principal. It must be of type {@link PublicKeyCredentialUserEntity}
		 * @param principal the principal to use
		 * @return the {@link Builder} for further configurations
		 */
		@Override
		public B principal(@Nullable Object principal) {
			Assert.isInstanceOf(PublicKeyCredentialUserEntity.class, principal,
					"principal must be of type PublicKeyCredentialUserEntity");
			this.principal = (PublicKeyCredentialUserEntity) principal;
			return (B) this;
		}

		@Override
		public WebAuthnAuthentication build() {
			return new WebAuthnAuthentication(this);
		}

	}

}
