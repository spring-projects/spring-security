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
package org.springframework.security.kt.docs.servlet.authorization.customizingauthorizationmanagers

import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.authorization.AuthorizationManagerFactory
import org.springframework.security.authorization.AuthorizationManagers
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import org.springframework.stereotype.Component

/**
 * Documentation for {@link AuthorizationManagerFactory}.
 *
 * @author Steve Riesenberg
 */
// tag::class[]
@Component
class CustomHttpRequestsAuthorizationManagerFactory : AuthorizationManagerFactory<RequestAuthorizationContext> {
    private val delegate = DefaultAuthorizationManagerFactory<RequestAuthorizationContext>()

    override fun authenticated(): AuthorizationManager<RequestAuthorizationContext> {
        return AuthorizationManagers.allOf(
            delegate.authenticated(),
            delegate.hasRole("USER")
        )
    }
}
// end::class[]


