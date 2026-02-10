package org.springframework.security.docs.servlet.oauth2.resourceserver.jwtgrantedauthoritiesspelexpression;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.junit.jupiter.api.Test;

import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.security.oauth2.server.resource.authentication.ExpressionJwtGrantedAuthoritiesConverter;

import static org.assertj.core.api.Assertions.assertThat;

class ExpressionJwtGrantedAuthoritiesConverterTests {

	@Test
	public void convertWhenTokenHasCustomClaimNameExpressionThenCustomClaimNameAttributeIsTranslatedToAuthorities() {
		// @formatter:off
		Jwt jwt = TestJwts.jwt()
				.claim("nested", Collections.singletonMap("scopes", Arrays.asList("read", "write")))
				.build();
		// @formatter:on
		// tag::spel-expression[]
		SpelExpressionParser parser = new SpelExpressionParser();
		Expression expression = parser.parseExpression("[nested][scopes]");
		ExpressionJwtGrantedAuthoritiesConverter converter = new ExpressionJwtGrantedAuthoritiesConverter(expression);
		Collection<GrantedAuthority> authorities = converter.convert(jwt);
		// end::spel-expression[]
		assertThat(authorities).extracting(GrantedAuthority::getAuthority)
				.containsExactly("SCOPE_read", "SCOPE_write");
	}
}
