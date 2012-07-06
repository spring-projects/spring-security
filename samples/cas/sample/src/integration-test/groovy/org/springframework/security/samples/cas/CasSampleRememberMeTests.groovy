/*
 * Copyright 2012 the original author or authors.
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
package org.springframework.security.samples.cas

import geb.spock.*

import org.junit.runner.RunWith;
import org.spockframework.runtime.Sputnik;
import org.springframework.security.samples.cas.pages.*

import spock.lang.Shared;
import spock.lang.Stepwise;

/**
 * Tests the remember-me feature in the CAS sample application.
 *
 * @author Jerome Leleu
 * @since 3.2.0
 */
@Stepwise
class CasSampleRememberMeTests extends AbstractCasTests {

    def 'access isFullyAuthenticated page, authenticate with rme, logout from application'() {
        when: 'Unauthenticated user accesses the isFullyAuthenticated page'
        to IsFullyAuthenticatedPage
        then: 'The login page is displayed'
        at LoginPage
        when: 'login with ROLE_USER after requesting the isFullyAuthenticated page'
        login 'scott', true
        then: 'the isFullyAuthenticated page is displayed'
        at IsFullyAuthenticatedPage
        navModule.logout.click()
     }
        
     def 'request isFullyAuthenticated page and be redirected to login page'() {    
        when: 'Unauthenticated user accesses the isFullyAuthenticated page'
        to IsFullyAuthenticatedPage
        then: 'The login page is displayed'
        at LoginPage        
    }

    def 'request isAuthenticated page and access to it'() {
        when: 'Unauthenticated user accesses the isAuthenticated page'
        to IsAuthenticatedPage
        then: 'The isAuthenticated page is displayed'
        at IsAuthenticatedPage
    }
}
