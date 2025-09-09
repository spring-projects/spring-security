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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Token Exchange Grant to
 * represent the principal in a composite token (e.g. the "delegation" use case).
 *
 * @author Steve Riesenberg
 * @since 7.0
 * @see OAuth2TokenExchangeAuthenticationToken
 */
public class OAuth2TokenExchangeCompositeAuthenticationToken extends AbstractAuthenticationToken {

	private final Authentication subject;

	private final List<OAuth2TokenExchangeActor> actors;

	public OAuth2TokenExchangeCompositeAuthenticationToken(Authentication subject,
			List<OAuth2TokenExchangeActor> actors) {
		super((subject != null) ? subject.getAuthorities() : null);
		Assert.notNull(subject, "subject cannot be null");
		Assert.notNull(actors, "actors cannot be null");
		this.subject = subject;
		this.actors = Collections.unmodifiableList(new ArrayList<>(actors));
		setDetails(subject.getDetails());
		setAuthenticated(subject.isAuthenticated());
	}

	@Override
	public Object getPrincipal() {
		return this.subject.getPrincipal();
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	public Authentication getSubject() {
		return this.subject;
	}

	public List<OAuth2TokenExchangeActor> getActors() {
		return this.actors;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof OAuth2TokenExchangeCompositeAuthenticationToken other)) {
			return false;
		}
		return super.equals(obj) && Objects.equals(this.subject, other.subject)
				&& Objects.equals(this.actors, other.actors);
	}

	@Override
	public int hashCode() {
		return Objects.hash(super.hashCode(), this.subject, this.actors);
	}

}
