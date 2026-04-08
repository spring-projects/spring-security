package org.springframework.security.kt.docs.servlet.oauth2.resourceserver.jwtgrantedauthoritiesspelexpression

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.tuple
import org.junit.jupiter.api.Test
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.jwt.TestJwts
import org.springframework.security.oauth2.server.resource.authentication.ExpressionJwtGrantedAuthoritiesConverter

class ExpressionJwtGrantedAuthoritiesConverterTests {
	@Test
	fun convertWhenTokenHasCustomClaimNameExpressionThenCustomClaimNameAttributeIsTranslatedToAuthorities() {
		// @formatter:off
		val jwt = TestJwts.jwt()
				.claim("nested", mapOf("scopes" to listOf("read", "write")))
				.build()
		// @formatter:on
        // tag::spel-expression[]
        val parser = SpelExpressionParser()
		val expression = parser.parseExpression("[nested][scopes]")
		val converter = ExpressionJwtGrantedAuthoritiesConverter(expression)
		val authorities = converter.convert(jwt)
        // end::spel-expression[]
		assertThat(authorities).extracting(GrantedAuthority::getAuthority)
            .containsExactly(tuple("SCOPE_read"), tuple("SCOPE_write"))
	}
}
