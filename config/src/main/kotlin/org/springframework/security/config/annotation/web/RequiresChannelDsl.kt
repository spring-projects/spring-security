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

@file:Suppress("DEPRECATION")

package org.springframework.security.config.annotation.web

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.ChannelSecurityConfigurer
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl
import org.springframework.security.web.access.channel.ChannelProcessor
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher
import org.springframework.security.web.util.matcher.AnyRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 * A Kotlin DSL to configure [HttpSecurity] channel security using idiomatic
 * Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property channelProcessors the [ChannelProcessor] instances to use in
 * [ChannelDecisionManagerImpl]
 */
@Deprecated(message="since 6.5 use redirectToHttps instead")
class RequiresChannelDsl : AbstractRequestMatcherDsl() {
    private val channelSecurityRules = mutableListOf<AuthorizationRule>()

    private val PATTERN_TYPE = PatternType.PATH

    var channelProcessors: List<ChannelProcessor>? = null

    /**
     * Adds a channel security rule.
     *
     * @param matches the [RequestMatcher] to match incoming requests against
     * @param attribute the configuration attribute to secure the matching request
     * (i.e. "REQUIRES_SECURE_CHANNEL")
     */
    fun secure(matches: RequestMatcher = AnyRequestMatcher.INSTANCE,
               attribute: String = "REQUIRES_SECURE_CHANNEL") {
        channelSecurityRules.add(MatcherAuthorizationRule(matches, attribute))
    }

    /**
     * Adds a request authorization rule for an endpoint matching the provided
     * pattern.
     * If Spring MVC is not an the classpath, it will use an ant matcher.
     * If Spring MVC is on the classpath, it will use an MVC matcher.
     * The MVC will use the same rules that Spring MVC uses for matching.
     * For example, often times a mapping of the path "/path" will match on
     * "/path", "/path/", "/path.html", etc.
     * If the current request will not be processed by Spring MVC, a reasonable default
     * using the pattern as an ant pattern will be used.
     *
     * @param pattern the pattern to match incoming requests against.
     * @param attribute the configuration attribute to secure the matching request
     * (i.e. "REQUIRES_SECURE_CHANNEL")
     */
    fun secure(pattern: String, attribute: String = "REQUIRES_SECURE_CHANNEL") {
        channelSecurityRules.add(PatternAuthorizationRule(pattern = pattern,
                                                          patternType = PATTERN_TYPE,
                                                          rule = attribute))
    }

    /**
     * Adds a request authorization rule for an endpoint matching the provided
     * pattern.
     * If Spring MVC is not an the classpath, it will use an ant matcher.
     * If Spring MVC is on the classpath, it will use an MVC matcher.
     * The MVC will use the same rules that Spring MVC uses for matching.
     * For example, often times a mapping of the path "/path" will match on
     * "/path", "/path/", "/path.html", etc.
     * If the current request will not be processed by Spring MVC, a reasonable default
     * using the pattern as an ant pattern will be used.
     *
     * @param pattern the pattern to match incoming requests against.
     * @param servletPath the servlet path to match incoming requests against. This
     * only applies when using an MVC pattern matcher.
     * @param attribute the configuration attribute to secure the matching request
     * (i.e. "REQUIRES_SECURE_CHANNEL")
     */
    fun secure(pattern: String, servletPath: String, attribute: String = "REQUIRES_SECURE_CHANNEL") {
        channelSecurityRules.add(PatternAuthorizationRule(pattern = pattern,
                                                          patternType = PATTERN_TYPE,
                                                          servletPath = servletPath,
                                                          rule = attribute))
    }

    /**
     * Specify channel security is active.
     */
    val requiresSecure = "REQUIRES_SECURE_CHANNEL"

    /**
     * Specify channel security is inactive.
     */
    val requiresInsecure = "REQUIRES_INSECURE_CHANNEL"

    internal fun get(): (ChannelSecurityConfigurer<HttpSecurity>.ChannelRequestMatcherRegistry) -> Unit {
        return { channelSecurity ->
            channelProcessors?.also { channelSecurity.channelProcessors(channelProcessors) }
            channelSecurityRules.forEach { rule ->
                when (rule) {
                    is MatcherAuthorizationRule -> channelSecurity.requestMatchers(rule.matcher).requires(rule.rule)
                    is PatternAuthorizationRule -> {
                        var builder = channelSecurity.applicationContext.getBeanProvider(
                            PathPatternRequestMatcher.Builder::class.java)
                            .getIfUnique(PathPatternRequestMatcher::withDefaults);
                        if (rule.servletPath != null) {
                            builder = builder.basePath(rule.servletPath)
                        }
                        channelSecurity.requestMatchers(builder.matcher(rule.httpMethod, rule.pattern)).requires(rule.rule)
                    }
                }
            }
        }
    }
}
