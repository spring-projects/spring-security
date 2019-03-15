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
 * Represents the extremely secure page of the CAS Sample application.
 *
 * @author Rob Winch
 */
class ExtremelySecurePage extends Page {
	static url = "secure/extreme/"
	static at = { assert $('h1').text() == 'VERY Secure Page'; true; }
	static content = {
		navModule { module NavModule }
	}
}