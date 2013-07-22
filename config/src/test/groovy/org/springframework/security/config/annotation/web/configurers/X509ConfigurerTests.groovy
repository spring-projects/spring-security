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

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter

/**
 *
 * @author Rob Winch
 */
class X509ConfigurerTests extends BaseSpringSpec {

    def "x509 ObjectPostProcessor"() {
        setup:
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
        when:
            http
                .x509()
                    .and()
                .build()

        then: "X509AuthenticationFilter is registered with LifecycleManager"
            1 * opp.postProcess(_ as X509AuthenticationFilter) >> {X509AuthenticationFilter o -> o}
    }

    def "invoke x509 twice does not override"() {
        setup:
            AnyObjectPostProcessor opp = Mock()
            HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
        when:
            http
                .x509()
                    .subjectPrincipalRegex(".*")
                    .and()
                .x509()
        then:
            http.getConfigurer(X509Configurer).subjectPrincipalRegex == ".*"
    }
}
