/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.config;

public abstract class ConfigTestUtils {

	public static final String AUTH_PROVIDER_XML = "<authentication-manager alias='authManager'>"
			+ "    <authentication-provider>" + "        <user-service id='us'>"
			+ "            <user name='bob' password='{noop}bobspassword' authorities='ROLE_A,ROLE_B' />"
			+ "            <user name='bill' password='{noop}billspassword' authorities='ROLE_A,ROLE_B,AUTH_OTHER' />"
			+ "            <user name='admin' password='{noop}password' authorities='ROLE_ADMIN,ROLE_USER' />"
			+ "            <user name='user' password='{noop}password' authorities='ROLE_USER' />"
			+ "        </user-service>" + "    </authentication-provider>" + "</authentication-manager>";

}
