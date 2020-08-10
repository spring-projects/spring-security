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
/**
 * The LDAP authentication provider package. Interfaces are provided for both
 * authentication and retrieval of user roles from an LDAP server.
 * <p>
 * The main provider class is <tt>LdapAuthenticationProvider</tt>. This is configured with
 * an <tt>LdapAuthenticator</tt> instance and an <tt>LdapAuthoritiesPopulator</tt>. The
 * latter is used to obtain the list of roles for the user.
 */
package org.springframework.security.ldap.authentication;
