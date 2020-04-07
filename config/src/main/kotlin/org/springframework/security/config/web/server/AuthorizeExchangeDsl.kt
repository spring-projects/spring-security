/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.config.web.server

import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.authorization.ReactiveAuthorizationManager
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.authorization.AuthorizationContext
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import org.springframework.security.web.util.matcher.RequestMatcher
import reactor.core.publisher.Mono

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] exchange authorization using idiomatic
 * Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 */
class AuthorizeExchangeDsl {
    private val authorizationRules = mutableListOf<ExchangeAuthorizationRule>()

    /**
     * Adds an exchange authorization rule for an endpoint matching the provided
     * matcher.
     *
     * @param matcher the [RequestMatcher] to match incoming requests against
     * @param access the [ReactiveAuthorizationManager] which determines the access
     * to the specific matcher.
     * Some predefined shortcuts have already been created, such as
     * [hasAnyAuthority], [hasAnyRole], [permitAll], [authenticated] and more
     */
    fun authorize(matcher: ServerWebExchangeMatcher = ServerWebExchangeMatchers.anyExchange(),
                  access: ReactiveAuthorizationManager<AuthorizationContext> = authenticated) {
        authorizationRules.add(MatcherExchangeAuthorizationRule(matcher, access))
    }

    /**
     * Adds an exchange authorization rule for an endpoint matching the provided
     * ant pattern.
     *
     * @param antPattern the ant ant pattern to match incoming requests against.
     * @param access the [ReactiveAuthorizationManager] which determines the access
     * to the specific matcher.
     * Some predefined shortcuts have already been created, such as
     * [hasAnyAuthority], [hasAnyRole], [permitAll], [authenticated] and more
     */
    fun authorize(antPattern: String, access: ReactiveAuthorizationManager<AuthorizationContext> = authenticated) {
        authorizationRules.add(PatternExchangeAuthorizationRule(antPattern, access))
    }

    /**
     * Matches any exchange.
     */
    val anyExchange: ServerWebExchangeMatcher = ServerWebExchangeMatchers.anyExchange()

    /**
     * Allow access for anyone.
     */
    val permitAll: ReactiveAuthorizationManager<AuthorizationContext> =
            ReactiveAuthorizationManager { _: Mono<Authentication>, _: AuthorizationContext -> Mono.just(AuthorizationDecision(true)) }

    /**
     * Deny access for everyone.
     */
    val denyAll: ReactiveAuthorizationManager<AuthorizationContext> =
            ReactiveAuthorizationManager { _: Mono<Authentication>, _: AuthorizationContext -> Mono.just(AuthorizationDecision(false)) }

    /**
     * Require a specific role. This is a shortcut for [hasAuthority].
     */
    fun hasRole(role: String): ReactiveAuthorizationManager<AuthorizationContext> =
            AuthorityReactiveAuthorizationManager.hasRole<AuthorizationContext>(role)

    /**
     * Require any specific role. This is a shortcut for [hasAnyAuthority].
     */
    fun hasAnyRole(vararg roles: String): ReactiveAuthorizationManager<AuthorizationContext> =
            AuthorityReactiveAuthorizationManager.hasAnyRole<AuthorizationContext>(*roles)

    /**
     * Require a specific authority.
     */
    fun hasAuthority(authority: String): ReactiveAuthorizationManager<AuthorizationContext> =
            AuthorityReactiveAuthorizationManager.hasAuthority<AuthorizationContext>(authority)

    /**
     * Require any authority.
     */
    fun hasAnyAuthority(vararg authorities: String): ReactiveAuthorizationManager<AuthorizationContext> =
            AuthorityReactiveAuthorizationManager.hasAnyAuthority<AuthorizationContext>(*authorities)

    /**
     * Require an authenticated user.
     */
    val authenticated: ReactiveAuthorizationManager<AuthorizationContext> =
            AuthenticatedReactiveAuthorizationManager.authenticated<AuthorizationContext>()

    internal fun get(): (ServerHttpSecurity.AuthorizeExchangeSpec) -> Unit {
        return { requests ->
            authorizationRules.forEach { rule ->
                when (rule) {
                    is MatcherExchangeAuthorizationRule -> requests.matchers(rule.matcher).access(rule.rule)
                    is PatternExchangeAuthorizationRule -> requests.pathMatchers(rule.pattern).access(rule.rule)
                }
            }
        }
    }

    private data class MatcherExchangeAuthorizationRule(val matcher: ServerWebExchangeMatcher,
                                                        override val rule: ReactiveAuthorizationManager<AuthorizationContext>) : ExchangeAuthorizationRule(rule)

    private data class PatternExchangeAuthorizationRule(val pattern: String,
                                                        override val rule: ReactiveAuthorizationManager<AuthorizationContext>) : ExchangeAuthorizationRule(rule)

    private abstract class ExchangeAuthorizationRule(open val rule: ReactiveAuthorizationManager<AuthorizationContext>)
}

