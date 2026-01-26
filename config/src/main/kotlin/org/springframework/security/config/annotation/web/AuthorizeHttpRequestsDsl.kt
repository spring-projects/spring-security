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

package org.springframework.security.config.annotation.web

import org.springframework.beans.factory.getBeanProvider
import org.springframework.context.ApplicationContext
import org.springframework.core.ResolvableType
import org.springframework.http.HttpMethod
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy
import org.springframework.security.access.hierarchicalroles.RoleHierarchy
import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.authorization.AuthorizationManagerFactory
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer
import org.springframework.security.config.core.GrantedAuthorityDefaults
import org.springframework.security.web.access.IpAddressAuthorizationManager
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher
import org.springframework.security.web.util.matcher.AnyRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 * A Kotlin DSL to configure [HttpSecurity] request authorization using idiomatic Kotlin code.
 *
 * @author Yuriy Savchenko
 * @since 5.7
 */
class AuthorizeHttpRequestsDsl : AbstractRequestMatcherDsl {

    private val authorizationRules = mutableListOf<AuthorizationManagerRule>()
    private val authorizationManagerFactory: AuthorizationManagerFactory<in RequestAuthorizationContext>

    private val PATTERN_TYPE = PatternType.PATH

    /**
     * Adds a request authorization rule.
     *
     * @param matches the [RequestMatcher] to match incoming requests against
     * @param access the [AuthorizationManager] to secure the matching request
     * (i.e. created via hasAuthority("ROLE_USER"))
     */
    fun authorize(matches: RequestMatcher = AnyRequestMatcher.INSTANCE,
                  access: AuthorizationManager<in RequestAuthorizationContext>) {
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
                  access: AuthorizationManager<in RequestAuthorizationContext>) {
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
                  access: AuthorizationManager<in RequestAuthorizationContext>) {
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
                  access: AuthorizationManager<in RequestAuthorizationContext>) {
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
                  access: AuthorizationManager<in RequestAuthorizationContext>) {
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
    fun hasAuthority(authority: String): AuthorizationManager<in RequestAuthorizationContext> = this.authorizationManagerFactory.hasAuthority(authority)

    /**
     * Specify that URLs require any of the provided authorities.
     *
     * @param authorities the authorities to require (i.e. ROLE_USER, ROLE_ADMIN, etc).
     * @return the [AuthorizationManager] with the provided authorities
     */
    fun hasAnyAuthority(vararg authorities: String): AuthorizationManager<in RequestAuthorizationContext> = this.authorizationManagerFactory.hasAnyAuthority(*authorities)


    /**
     * Specify that URLs require any of the provided authorities.
     *
     * @param authorities the authorities to require (i.e. ROLE_USER, ROLE_ADMIN, etc).
     * @return the [AuthorizationManager] with the provided authorities
     */
    fun hasAllAuthorities(vararg authorities: String): AuthorizationManager<in RequestAuthorizationContext> = this.authorizationManagerFactory.hasAllAuthorities(*authorities)

    /**
     * Specify that URLs require a particular role.
     *
     * @param role the role to require (i.e. USER, ADMIN, etc).
     * @return the [AuthorizationManager] with the provided role
     */
    fun hasRole(role: String): AuthorizationManager<in RequestAuthorizationContext> = this.authorizationManagerFactory.hasRole(role)

    /**
     * Specify that URLs require any of the provided roles.
     *
     * @param roles the roles to require (i.e. USER, ADMIN, etc).
     * @return the [AuthorizationManager] with the provided roles
     */
    fun hasAnyRole(vararg roles: String): AuthorizationManager<in RequestAuthorizationContext> = this.authorizationManagerFactory.hasAnyRole(*roles)

    /**
     * Specify that URLs require any of the provided roles.
     *
     * @param roles the roles to require (i.e. USER, ADMIN, etc).
     * @return the [AuthorizationManager] with the provided roles
     */
    fun hasAllRoles(vararg roles: String): AuthorizationManager<in RequestAuthorizationContext> = this.authorizationManagerFactory.hasAllRoles(*roles)

    /**
     * Require a specific IP or range of IP addresses.
     * @since 6.3
     */
    fun hasIpAddress(ipAddress: String): AuthorizationManager<RequestAuthorizationContext> =
        IpAddressAuthorizationManager.hasIpAddress(ipAddress)

    /**
     * Specify that URLs are allowed by anyone.
     */
    val permitAll: AuthorizationManager<in RequestAuthorizationContext>

    /**
     * Specify that URLs are not allowed by anyone.
     */
    val denyAll: AuthorizationManager<in RequestAuthorizationContext>

    /**
     * Specify that URLs are allowed by any authenticated user.
     */
    val authenticated: AuthorizationManager<in RequestAuthorizationContext>

    /**
     * Specify that URLs are allowed by users who have authenticated and were not "remembered".
     * @since 6.5
     */
    val fullyAuthenticated: AuthorizationManager<in RequestAuthorizationContext>

    internal fun get(): (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry) -> Unit {
        return { requests ->
            authorizationRules.forEach { rule ->
                when (rule) {
                    is MatcherAuthorizationManagerRule -> requests.requestMatchers(rule.matcher).access(rule.rule)
                    is PatternAuthorizationManagerRule -> {
                        var builder = requests.applicationContext.getBeanProvider(
                            PathPatternRequestMatcher.Builder::class.java)
                            .getIfUnique(PathPatternRequestMatcher::withDefaults)
                        if (rule.servletPath != null) {
                            builder = builder.basePath(rule.servletPath)
                        }
                        requests.requestMatchers(builder.matcher(rule.httpMethod, rule.pattern)).access(rule.rule)
                    }
                }
            }
        }
    }

    constructor(context: ApplicationContext) {
        this.authorizationManagerFactory =  resolveAuthorizationManagerFactory(context)
        this.authenticated = this.authorizationManagerFactory.authenticated()
        this.denyAll = this.authorizationManagerFactory.denyAll()
        this.fullyAuthenticated = this.authorizationManagerFactory.fullyAuthenticated()
        this.permitAll = this.authorizationManagerFactory.permitAll()
    }

    private fun resolveAuthorizationManagerFactory(context: ApplicationContext): AuthorizationManagerFactory<in RequestAuthorizationContext> {
        val factoryOfRequestAuthorizationContext = context.getBeanProvider<AuthorizationManagerFactory<RequestAuthorizationContext>>().getIfUnique()
        if (factoryOfRequestAuthorizationContext != null) {
            return factoryOfRequestAuthorizationContext
        }
        val factoryOfObjectType = ResolvableType.forClassWithGenerics(AuthorizationManagerFactory::class.java, Any::class.java)
        val factoryOfAny = context.getBeanProvider<AuthorizationManagerFactory<Any>>(factoryOfObjectType).getIfUnique()
        if (factoryOfAny != null) {
            return factoryOfAny
        }
        val defaultFactory: DefaultAuthorizationManagerFactory<RequestAuthorizationContext> = DefaultAuthorizationManagerFactory()
        val rolePrefix = resolveRolePrefix(context)
        if (rolePrefix != null) {
            defaultFactory.setRolePrefix(rolePrefix)
        }
        val roleHierarchy = resolveRoleHierarchy(context)
        if (roleHierarchy != null) {
            defaultFactory.setRoleHierarchy(roleHierarchy)
        }
        return defaultFactory
    }

    private fun resolveRolePrefix(context: ApplicationContext): String? {
        val beanNames = context.getBeanNamesForType(GrantedAuthorityDefaults::class.java)
        if (beanNames.isNotEmpty()) {
            return context.getBean(GrantedAuthorityDefaults::class.java).rolePrefix
        }
        return null
    }

    private fun resolveRoleHierarchy(context: ApplicationContext): RoleHierarchy? {
        val beanNames = context.getBeanNamesForType(RoleHierarchy::class.java)
        if (beanNames.isNotEmpty()) {
            return context.getBean(RoleHierarchy::class.java)
        }
        return null
    }

}
