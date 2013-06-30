/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configurers

import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.preauth.j2ee.J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter

/**
 *
 * @author Rob Winch
 */
class JeeConfigurerTests extends BaseSpringSpec {

    def "jee ObjectPostProcessor"() {
        setup:
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
        when:
            http
                .jee()
                    .and()
                .build()

        then: "J2eePreAuthenticatedProcessingFilter is registered with LifecycleManager"
            1 * opp.postProcess(_ as J2eePreAuthenticatedProcessingFilter) >> {J2eePreAuthenticatedProcessingFilter o -> o}
        and: "J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource is registered with LifecycleManager"
            1 * opp.postProcess(_ as J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource) >> {J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource o -> o}
    }
}
