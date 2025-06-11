/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.kt.docs.servlet.test.testmethodwithsecuritycontext

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.test.context.support.WithSecurityContextFactory
import org.springframework.security.test.context.support.WithUserDetails
import org.springframework.util.Assert

// tag::snippet[]
class WithUserDetailsSecurityContextFactory @Autowired constructor(private val userDetailsService: UserDetailsService) :
    WithSecurityContextFactory<WithUserDetails> {

    override fun createSecurityContext(withUser: WithUserDetails): SecurityContext {
        val username: String = withUser.value
        Assert.hasLength(username, "value() must be non-empty String")
        val principal = userDetailsService.loadUserByUsername(username)
        val authentication: Authentication =
            UsernamePasswordAuthenticationToken(principal, principal.password, principal.authorities)
        val context = SecurityContextHolder.createEmptyContext()
        context.authentication = authentication
        return context
    }

}
// end::snippet[]
