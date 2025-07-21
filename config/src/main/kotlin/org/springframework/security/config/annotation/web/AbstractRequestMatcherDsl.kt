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
import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import org.springframework.security.web.util.matcher.AnyRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 * A base class that provides authorization rules for [RequestMatcher]s and patterns.
 *
 * @author Eleftheria Stein
 * @since 5.3
 */
@SecurityMarker
abstract class AbstractRequestMatcherDsl {
    /**
     * Matches any request.
     */
    val anyRequest: RequestMatcher = AnyRequestMatcher.INSTANCE

    protected data class MatcherAuthorizationRule(val matcher: RequestMatcher,
                                                  override val rule: String) : AuthorizationRule(rule)

    protected data class MatcherAuthorizationManagerRule(val matcher: RequestMatcher,
                                                         override val rule: AuthorizationManager<RequestAuthorizationContext>) : AuthorizationManagerRule(rule)

    protected data class PatternAuthorizationRule(val pattern: String,
                                                  val patternType: PatternType,
                                                  val servletPath: String? = null,
                                                  val httpMethod: HttpMethod? = null,
                                                  override val rule: String) : AuthorizationRule(rule)

    protected data class PatternAuthorizationManagerRule(val pattern: String,
                                                         val patternType: PatternType,
                                                         val servletPath: String? = null,
                                                         val httpMethod: HttpMethod? = null,
                                                         override val rule: AuthorizationManager<RequestAuthorizationContext>) : AuthorizationManagerRule(rule)

    protected abstract class AuthorizationRule(open val rule: String)

    protected abstract class AuthorizationManagerRule(open val rule: AuthorizationManager<RequestAuthorizationContext>)

    protected enum class PatternType {
        ANT, MVC, PATH;
    }
}
