package org.springframework.security.kt.docs.servlet.authentication.servletauthenticationauthentication

import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers
import org.mockito.BDDMockito
import org.mockito.Mockito
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.SecurityAssertions
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.ott.OneTimeTokenAuthentication
import org.springframework.security.core.Authentication
import org.springframework.security.core.BuildableAuthentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.authority.FactorGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder

class CopyAuthoritiesTests {
    @Test
    fun toBuilderWhenApplyThenCopies() {
        val previous: Authentication = UsernamePasswordAuthenticationToken("alice", "pass",
            AuthorityUtils.createAuthorityList(FactorGrantedAuthority.PASSWORD_AUTHORITY))
        SecurityContextHolder.getContext().authentication = previous
        var latest: Authentication = OneTimeTokenAuthentication("bob",
            AuthorityUtils.createAuthorityList(FactorGrantedAuthority.OTT_AUTHORITY))
        val authenticationManager: AuthenticationManager = Mockito.mock(AuthenticationManager::class.java)
        BDDMockito.given(authenticationManager.authenticate(ArgumentMatchers.any())).willReturn(latest)
        val authenticationRequest: Authentication = TestingAuthenticationToken("user", "pass")
        // tag::springSecurity[]
        var latestResult: Authentication = authenticationManager.authenticate(authenticationRequest)
        val previousResult = SecurityContextHolder.getContext().authentication;
        if (previousResult?.isAuthenticated == true && latestResult is BuildableAuthentication) {
            latestResult = latestResult.toBuilder().authorities { a ->
                a.addAll(previousResult.authorities)
            }.build()
        }
        // end::springSecurity[]
        SecurityAssertions.assertThat(latestResult).hasAuthorities(
            FactorGrantedAuthority.PASSWORD_AUTHORITY,
            FactorGrantedAuthority.OTT_AUTHORITY
        )
        SecurityContextHolder.clearContext()
    }
}
