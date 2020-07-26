/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security;

import javax.servlet.ServletRequest;

import org.springframework.security.web.PortResolver;

/**
 * Always returns the constructor-specified HTTP and HTTPS ports.
 *
 * @author Ben Alex
 */
public class MockPortResolver implements PortResolver {

	private int http = 80;

	private int https = 443;

	public MockPortResolver(int http, int https) {
		this.http = http;
		this.https = https;
	}

	public int getServerPort(ServletRequest request) {
		if ((request.getScheme() != null) && request.getScheme().equals("https")) {
			return this.https;
		}
		else {
			return this.http;
		}
	}

}
