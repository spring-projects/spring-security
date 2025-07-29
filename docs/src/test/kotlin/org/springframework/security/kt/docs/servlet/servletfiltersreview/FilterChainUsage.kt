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

package org.springframework.security.kt.docs.servlet.servletfiltersreview

import jakarta.servlet.*
import java.io.IOException

/**
 * Demos FilterChain Usage.
 * @author Rob Winch
 */
class FilterChainUsage : Filter {

    // tag::dofilter[]
    @Throws(IOException::class, ServletException::class)
    override fun doFilter(request: ServletRequest?, response: ServletResponse?, chain: FilterChain) {
        // do something before the rest of the application
        chain.doFilter(request, response) // invoke the rest of the application
        // do something after the rest of the application
    }
    // end::dofilter[]

}
