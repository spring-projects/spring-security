/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.convert.converter.Converter;
import org.springframework.core.log.LogMessage;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * Uses an expression for extracting the token claim value to use for mapping
 * {@link GrantedAuthority authorities}.
 *
 * Note this can be used in combination with a
 * {@link DelegatingJwtGrantedAuthoritiesConverter}.
 *
 * @author Thomas Darimont
 * @since 6.4
 */
public final class ExpressionJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

	private final Log logger = LogFactory.getLog(getClass());

	private String authorityPrefix = "SCOPE_";

	private final Expression authoritiesClaimExpression;

	/**
	 * Constructs a {@link ExpressionJwtGrantedAuthoritiesConverter} using the provided
	 * {@code authoritiesClaimExpression}.
	 * @param authoritiesClaimExpression The token claim SpEL Expression to map
	 * authorities from.
	 */
	public ExpressionJwtGrantedAuthoritiesConverter(Expression authoritiesClaimExpression) {
		Assert.notNull(authoritiesClaimExpression, "authoritiesClaimExpression must not be null");
		this.authoritiesClaimExpression = authoritiesClaimExpression;
	}

	/**
	 * Sets the prefix to use for {@link GrantedAuthority authorities} mapped by this
	 * converter. Defaults to {@code "SCOPE_"}.
	 * @param authorityPrefix The authority prefix
	 */
	public void setAuthorityPrefix(String authorityPrefix) {
		Assert.notNull(authorityPrefix, "authorityPrefix cannot be null");
		this.authorityPrefix = authorityPrefix;
	}

	/**
	 * Extract {@link GrantedAuthority}s from the given {@link Jwt}.
	 * @param jwt The {@link Jwt} token
	 * @return The {@link GrantedAuthority authorities} read from the token scopes
	 */
	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
		for (String authority : getAuthorities(jwt)) {
			grantedAuthorities.add(new SimpleGrantedAuthority(this.authorityPrefix + authority));
		}
		return grantedAuthorities;
	}

	private Collection<String> getAuthorities(Jwt jwt) {
		Object authorities;
		try {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Looking for authorities with expression. expression=%s",
						this.authoritiesClaimExpression.getExpressionString()));
			}
			authorities = this.authoritiesClaimExpression.getValue(jwt.getClaims(), Collection.class);
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Found authorities with expression. authorities=%s", authorities));
			}
		}
		catch (ExpressionException ee) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Failed to evaluate expression. error=%s", ee.getMessage()));
			}
			authorities = Collections.emptyList();
		}

		if (authorities != null) {
			return castAuthoritiesToCollection(authorities);
		}
		return Collections.emptyList();
	}

	@SuppressWarnings("unchecked")
	private Collection<String> castAuthoritiesToCollection(Object authorities) {
		return (Collection<String>) authorities;
	}

}
