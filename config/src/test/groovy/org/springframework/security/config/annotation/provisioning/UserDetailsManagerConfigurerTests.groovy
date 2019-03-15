/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.provisioning

import org.springframework.security.config.annotation.authentication.configurers.provisioning.UserDetailsManagerConfigurer;
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.provisioning.InMemoryUserDetailsManager

import spock.lang.Specification

/**
 *
 * @author Rob Winch
 *
 */
class UserDetailsManagerConfigurerTests extends Specification {

    def "all attributes supported"() {
        setup:
            InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager([])
        when:
            UserDetails userDetails = new UserDetailsManagerConfigurer<UserDetailsManagerConfigurer<InMemoryUserDetailsManager>>(userDetailsManager)
                .withUser("user")
                    .password("password")
                    .roles("USER")
                    .disabled(true)
                    .accountExpired(true)
                    .accountLocked(true)
                    .credentialsExpired(true)
                    .build()
        then:
            userDetails.username == 'user'
            userDetails.password == 'password'
            userDetails.authorities.collect { it.authority } == ["ROLE_USER"]
            !userDetails.accountNonExpired
            !userDetails.accountNonLocked
            !userDetails.credentialsNonExpired
            !userDetails.enabled
    }

    def "authorities(GrantedAuthorities...) works"() {
        setup:
            InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager([])
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER")
        when:
            UserDetails userDetails = new UserDetailsManagerConfigurer<UserDetailsManagerConfigurer<InMemoryUserDetailsManager>>(userDetailsManager)
                .withUser("user")
                    .password("password")
                    .authorities(authority)
                    .build()
        then:
            userDetails.authorities == [authority] as Set
    }

    def "authorities(String...) works"() {
        setup:
            InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager([])
            String authority = "ROLE_USER"
        when:
            UserDetails userDetails = new UserDetailsManagerConfigurer<UserDetailsManagerConfigurer<InMemoryUserDetailsManager>>(userDetailsManager)
                .withUser("user")
                    .password("password")
                    .authorities(authority)
                    .build()
        then:
            userDetails.authorities.collect { it.authority } == [authority]
    }


    def "authorities(List) works"() {
        setup:
            InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager([])
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER")
        when:
            UserDetails userDetails = new UserDetailsManagerConfigurer<UserDetailsManagerConfigurer<InMemoryUserDetailsManager>>(userDetailsManager)
                .withUser("user")
                    .password("password")
                    .authorities([authority])
                    .build()
        then:
            userDetails.authorities == [authority] as Set
    }
}
