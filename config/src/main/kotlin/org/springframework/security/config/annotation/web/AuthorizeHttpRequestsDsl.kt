/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web

import org.springframework.http.HttpMethod
import org.springframework.security.authorization.AuthenticatedAuthorizationManager
import org.springframework.security.authorization.AuthorityAuthorizationManager
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.web.access.intercept.AuthorizationFilter
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher
import org.springframework.security.web.util.matcher.AnyRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.util.ClassUtils
import org.springframework.web.servlet.handler.HandlerMappingIntrospector
import java.util.function.Supplier

/**
 * A Kotlin DSL to configure [HttpSecurity] request authorization using idiomatic Kotlin code.
 *
 * @author Yuriy Savchenko
 * @since 5.7
 * @property shouldFilterAllDispatcherTypes whether the [AuthorizationFilter] should filter all dispatcher types
 */
class AuthorizeHttpRequestsDsl : AbstractRequestMatcherDsl() {
    var shouldFilterAllDispatcherTypes: Boolean? = null

    private val authorizationRules = mutableListOf<AuthorizationManagerRule>()

    private val HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME = "mvcHandlerMappingIntrospector"
    private val HANDLER_MAPPING_INTROSPECTOR = "org.springframework.web.servlet.handler.HandlerMappingIntrospector"
    private val MVC_PRESENT = ClassUtils.isPresent(
        HANDLER_MAPPING_INTROSPECTOR,
        AuthorizeHttpRequestsDsl::class.java.classLoader)
    private val PATTERN_TYPE = if (MVC_PRESENT) PatternType.MVC else PatternType.ANT

    /**
     * Adds a request authorization rule.
     *
     * @param matches the [RequestMatcher] to match incoming requests against
     * @param access the [AuthorizationManager] to secure the matching request
     * (i.e. created via hasAuthority("ROLE_USER"))
     */
    fun authorize(matches: RequestMatcher = AnyRequestMatcher.INSTANCE,
                  access: AuthorizationManager<RequestAuthorizationContext>) {
        authorizationRules.add(MatcherAuthorizationManagerRule(matches, access))
    }

    /**
     * Adds a request authorization rule for an endpoint matching the provided
     * pattern.
     * If Spring MVC is on the classpath, it will use an MVC matcher.
     * If Spring MVC is not on the classpath, it will use an ant matcher.
     * The MVC will use the same rules that Spring MVC uses for matching.
     * For example, often times a mapping of the path "/path" will match on
     * "/path", "/path/", "/path.html", etc.
     * If the current request will not be processed by Spring MVC, a reasonable default
     * using the pattern as an ant pattern will be used.
     *
     * @param pattern the pattern to match incoming requests against.
     * @param access the [AuthorizationManager] to secure the matching request
     * (i.e. created via hasAuthority("ROLE_USER"))
     */
    fun authorize(pattern: String,
                  access: AuthorizationManager<RequestAuthorizationContext>) {
        authorizationRules.add(
            PatternAuthorizationManagerRule(
                pattern = pattern,
                patternType = PATTERN_TYPE,
                rule = access
            )
        )
    }

    /**
     * Adds a request authorization rule for an endpoint matching the provided
     * pattern.
     * If Spring MVC is on the classpath, it will use an MVC matcher.
     * If Spring MVC is not on the classpath, it will use an ant matcher.
     * The MVC will use the same rules that Spring MVC uses for matching.
     * For example, often times a mapping of the path "/path" will match on
     * "/path", "/path/", "/path.html", etc.
     * If the current request will not be processed by Spring MVC, a reasonable default
     * using the pattern as an ant pattern will be used.
     *
     * @param method the HTTP method to match the income requests against.
     * @param pattern the pattern to match incoming requests against.
     * @param access the [AuthorizationManager] to secure the matching request
     * (i.e. created via hasAuthority("ROLE_USER"))
     */
    fun authorize(method: HttpMethod,
                  pattern: String,
                  access: AuthorizationManager<RequestAuthorizationContext>) {
        authorizationRules.add(
            PatternAuthorizationManagerRule(
                pattern = pattern,
                patternType = PATTERN_TYPE,
                httpMethod = method,
                rule = access
            )
        )
    }

    /**
     * Adds a request authorization rule for an endpoint matching the provided
     * pattern.
     * If Spring MVC is on the classpath, it will use an MVC matcher.
     * If Spring MVC is not on the classpath, it will use an ant matcher.
     * The MVC will use the same rules that Spring MVC uses for matching.
     * For example, often times a mapping of the path "/path" will match on
     * "/path", "/path/", "/path.html", etc.
     * If the current request will not be processed by Spring MVC, a reasonable default
     * using the pattern as an ant pattern will be used.
     *
     * @param pattern the pattern to match incoming requests against.
     * @param servletPath the servlet path to match incoming requests against. This
     * only applies when using an MVC pattern matcher.
     * @param access the [AuthorizationManager] to secure the matching request
     * (i.e. created via hasAuthority("ROLE_USER"))
     */
    fun authorize(pattern: String,
                  servletPath: String,
                  access: AuthorizationManager<RequestAuthorizationContext>) {
        authorizationRules.add(
            PatternAuthorizationManagerRule(
                pattern = pattern,
                patternType = PATTERN_TYPE,
                servletPath = servletPath,
                rule = access
            )
        )
    }

    /**
     * Adds a request authorization rule for an endpoint matching the provided
     * pattern.
     * If Spring MVC is on the classpath, it will use an MVC matcher.
     * If Spring MVC is not on the classpath, it will use an ant matcher.
     * The MVC will use the same rules that Spring MVC uses for matching.
     * For example, often times a mapping of the path "/path" will match on
     * "/path", "/path/", "/path.html", etc.
     * If the current request will not be processed by Spring MVC, a reasonable default
     * using the pattern as an ant pattern will be used.
     *
     * @param method the HTTP method to match the income requests against.
     * @param pattern the pattern to match incoming requests against.
     * @param servletPath the servlet path to match incoming requests against. This
     * only applies when using an MVC pattern matcher.
     * @param access the [AuthorizationManager] to secure the matching request
     * (i.e. created via hasAuthority("ROLE_USER"))
     */
    fun authorize(method: HttpMethod,
                  pattern: String,
                  servletPath: String,
                  access: AuthorizationManager<RequestAuthorizationContext>) {
        authorizationRules.add(
            PatternAuthorizationManagerRule(
                pattern = pattern,
                patternType = PATTERN_TYPE,
                servletPath = servletPath,
                httpMethod = method,
                rule = access
            )
        )
    }

    /**
     * Specify that URLs require a particular authority.
     *
     * @param authority the authority to require (i.e. ROLE_USER, ROLE_ADMIN, etc).
     * @return the [AuthorizationManager] with the provided authority
     */
    fun hasAuthority(authority: String): AuthorizationManager<RequestAuthorizationContext> {
        return AuthorityAuthorizationManager.hasAuthority(authority)
    }

    /**
     * Specify that URLs require any of the provided authorities.
     *
     * @param authorities the authorities to require (i.e. ROLE_USER, ROLE_ADMIN, etc).
     * @return the [AuthorizationManager] with the provided authorities
     */
    fun hasAnyAuthority(vararg authorities: String): AuthorizationManager<RequestAuthorizationContext> {
        return AuthorityAuthorizationManager.hasAnyAuthority(*authorities)
    }

    /**
     * Specify that URLs require a particular role.
     *
     * @param role the role to require (i.e. USER, ADMIN, etc).
     * @return the [AuthorizationManager] with the provided role
     */
    fun hasRole(role: String): AuthorizationManager<RequestAuthorizationContext> {
        return AuthorityAuthorizationManager.hasRole(role)
    }

    /**
     * Specify that URLs require any of the provided roles.
     *
     * @param roles the roles to require (i.e. USER, ADMIN, etc).
     * @return the [AuthorizationManager] with the provided roles
     */
    fun hasAnyRole(vararg roles: String): AuthorizationManager<RequestAuthorizationContext> {
        return AuthorityAuthorizationManager.hasAnyRole(*roles)
    }

    /**
     * Specify that URLs are allowed by anyone.
     */
    val permitAll: AuthorizationManager<RequestAuthorizationContext> =
        AuthorizationManager { _: Supplier<Authentication>, _: RequestAuthorizationContext -> AuthorizationDecision(true) }

    /**
     * Specify that URLs are not allowed by anyone.
     */
    val denyAll: AuthorizationManager<RequestAuthorizationContext> =
        AuthorizationManager { _: Supplier<Authentication>, _: RequestAuthorizationContext -> AuthorizationDecision(false) }

    /**
     * Specify that URLs are allowed by any authenticated user.
     */
    val authenticated: AuthorizationManager<RequestAuthorizationContext> =
        AuthenticatedAuthorizationManager.authenticated()

    internal fun get(): (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry) -> Unit {
        return { requests ->
            authorizationRules.forEach { rule ->
                when (rule) {
                    is MatcherAuthorizationManagerRule -> requests.requestMatchers(rule.matcher).access(rule.rule)
                    is PatternAuthorizationManagerRule -> {
                        when (rule.patternType) {
                            PatternType.ANT -> requests.requestMatchers(rule.httpMethod, rule.pattern).access(rule.rule)
                            PatternType.MVC -> {
                                val introspector = requests.applicationContext.getBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME, HandlerMappingIntrospector::class.java)
                                val mvcMatcher = MvcRequestMatcher.Builder(introspector)
                                    .servletPath(rule.servletPath)
                                    .pattern(rule.pattern)
                                mvcMatcher.setMethod(rule.httpMethod)
                                requests.requestMatchers(mvcMatcher).access(rule.rule)
                            }
                        }
                    }
                }
            }
            shouldFilterAllDispatcherTypes?.also { shouldFilter ->
                requests.shouldFilterAllDispatcherTypes(shouldFilter)
            }
        }
    }
}
