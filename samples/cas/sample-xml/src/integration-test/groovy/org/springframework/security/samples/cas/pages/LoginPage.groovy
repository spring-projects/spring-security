/*
 * Copyright 2011 the original author or authors.
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
package org.springframework.security.samples.cas.pages;

import geb.*

/**
 * The CAS login page.
 *
 * @author Rob Winch
 */
class LoginPage extends Page {
    static url = loginUrl()
    static at = { assert driver.currentUrl.startsWith(loginUrl()); true}
    static content = {
        login(required:false) { user, password=user ->
            loginForm.username = user
            loginForm.password = password
            submit.click()
        }
        loginForm { $('#login') }
        submit { $('input', type: 'submit') }
    }

    /**
     * Gets the login page url which might change based upon the system properties. This is to support using a randomly available port for CI.
     * @return
     */
    private static String loginUrl() {
        def host = System.getProperty('cas.server.host', 'localhost:9443')
        "https://${host}/cas/login"
    }
}