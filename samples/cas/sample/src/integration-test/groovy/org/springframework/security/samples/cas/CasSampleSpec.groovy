/*
 * Copyright 2011 the original author or authors.
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
 * Tests the CAS sample application using service tickets.
 *
 * @author Rob Winch
 */
@Stepwise
class CasSampleSpec extends BaseSpec {
    @Shared String casServerLogoutUrl = LoginPage.url.replaceFirst('/login','/logout')

    def 'access home page with unauthenticated user succeeds'() {
        when: 'Unauthenticated user accesses the Home Page'
        to HomePage
        then: 'The home page succeeds'
        at HomePage
    }

    def 'access extremely secure page with unauthenitcated user requires login'() {
        when: 'Unauthenticated user accesses the extremely secure page'
        to ExtremelySecurePage
        then: 'The login page is displayed'
        at LoginPage
    }

    def 'authenticate attempt with invaid ticket fails'() {
        when: 'present invalid ticket'
        go "j_spring_cas_security_check?ticket=invalid"
        then: 'the login failed page is displayed'
        println driver.pageSource
        $("h2").text() == 'Login to CAS failed!'
    }

    def 'access secure page with unauthenticated user requires login'() {
        when: 'Unauthenticated user accesses the secure page'
        to SecurePage
        then: 'The login page is displayed'
        at LoginPage
    }

    def 'saved request is used for secure page'() {
        when: 'login with ROLE_USER after requesting the secure page'
        login 'scott'
        then: 'the secure page is displayed'
        at SecurePage
    }

    def 'access proxy ticket sample with ROLE_USER is allowed'() {
        when: 'user with ROLE_USER requests the proxy ticket sample page'
        to ProxyTicketSamplePage
        then: 'the proxy ticket sample page is displayed'
        at ProxyTicketSamplePage
    }

    def 'access extremely secure page with ROLE_USER is denied'() {
        when: 'User with ROLE_USER accesses extremely secure page'
        to ExtremelySecurePage
        then: 'the access denied page is displayed'
        at AccessDeniedPage
    }

    def 'clicking local logout link displays local logout page'() {
        setup: 'Navigate to page with logout link'
        to SecurePage
        when: 'Local logout link is clicked'
        navModule.logout.click()
        then: 'the local logout page is displayed'
        at LocalLogoutPage
    }

    def 'clicking cas server logout link successfully performs logout'() {
        when: 'the cas server logout link is clicked and the secure page is requested'
        casServerLogout.click()
        to SecurePage
        then: 'the login page is displayed'
        at LoginPage
    }

    def 'access extremely secure page with ROLE_SUPERVISOR succeeds'() {
        setup: 'login with ROLE_SUPERVISOR'
        login 'rod'
        when: 'access extremely secure page'
        to ExtremelySecurePage
        then: 'extremely secure page is displayed'
        at ExtremelySecurePage
    }

    def 'after logout extremely secure page requires login'() {
        when: 'logout and request extremely secure page'
        navModule.logout.click()
        casServerLogout.click()
        to ExtremelySecurePage
        then: 'login page is displayed'
        at LoginPage
    }

    def 'logging out of the cas server successfully logs out of the cas sample application'() {
        setup: 'login with ROLE_USER'
        to SecurePage
        at LoginPage
        login 'rod'
        at SecurePage
        when: 'logout of the CAS Server'
        go casServerLogoutUrl
        to SecurePage
        then: 'user is logged out of the CAS Service'
        at LoginPage
    }
}