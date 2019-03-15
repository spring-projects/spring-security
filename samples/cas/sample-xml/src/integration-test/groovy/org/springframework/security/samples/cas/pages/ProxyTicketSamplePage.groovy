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
import org.springframework.security.samples.cas.modules.*


/**
 * Represents the proxy ticket sample page within the CAS Sample application.
 *
 * @author Rob Winch
 */
class ProxyTicketSamplePage extends Page {
    static url = "secure/ptSample"
    static at = { assert $('h1').text() == 'Secure Page using a Proxy Ticket'; true}
    static content = {
        navModule { module NavModule }
    }
}