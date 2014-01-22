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
package org.springframework.security.samples.cas.pages;

import geb.*


/**
 * This represents the local logout page. This page is where the user is logged out of the CAS Sample application, but
 * since the user is still logged into the CAS Server accessing a protected page within the CAS Sample application would result
 * in SSO occurring again. To fully logout, the user should click the cas server logout url which logs out of the cas server and performs
 * single logout on the other services.
 *
 * @author Rob Winch
 */
class LocalLogoutPage extends Page {
    static url = 'cas-logout.jsp'
    static at = { assert driver.currentUrl.endsWith(url); true }
    static content = {
        casServerLogout { $('a',text: 'Logout of CAS') }
    }
}
