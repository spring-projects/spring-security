/*
 * Copyright 2002-2022 the original author or authors.
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

/**
 * Contains all the element names used by Spring Security 3 namespace support.
 *
 * @author Ben Alex
 * @author Evgeniy Cheban
 */
public abstract class Elements {

	public static final String ACCESS_DENIED_HANDLER = "access-denied-handler";

	public static final String AUTHENTICATION_MANAGER = "authentication-manager";

	public static final String AFTER_INVOCATION_PROVIDER = "after-invocation-provider";

	public static final String USER_SERVICE = "user-service";

	public static final String JDBC_USER_SERVICE = "jdbc-user-service";

	public static final String FILTER_CHAIN_MAP = "filter-chain-map";

	public static final String INTERCEPT_METHODS = "intercept-methods";

	public static final String INTERCEPT_URL = "intercept-url";

	public static final String AUTHENTICATION_PROVIDER = "authentication-provider";

	public static final String HTTP = "http";

	public static final String LDAP_PROVIDER = "ldap-authentication-provider";

	public static final String LDAP_SERVER = "ldap-server";

	public static final String LDAP_USER_SERVICE = "ldap-user-service";

	public static final String PROTECT_POINTCUT = "protect-pointcut";

	public static final String EXPRESSION_HANDLER = "expression-handler";

	public static final String INVOCATION_HANDLING = "pre-post-annotation-handling";

	public static final String INVOCATION_ATTRIBUTE_FACTORY = "invocation-attribute-factory";

	public static final String PRE_INVOCATION_ADVICE = "pre-invocation-advice";

	public static final String POST_INVOCATION_ADVICE = "post-invocation-advice";

	public static final String PROTECT = "protect";

	public static final String SESSION_MANAGEMENT = "session-management";

	public static final String CONCURRENT_SESSIONS = "concurrency-control";

	public static final String LOGOUT = "logout";

	public static final String FORM_LOGIN = "form-login";

	public static final String BASIC_AUTH = "http-basic";

	public static final String REMEMBER_ME = "remember-me";

	public static final String ANONYMOUS = "anonymous";

	public static final String FILTER_CHAIN = "filter-chain";

	public static final String GLOBAL_METHOD_SECURITY = "global-method-security";

	public static final String METHOD_SECURITY = "method-security";

	public static final String PASSWORD_ENCODER = "password-encoder";

	public static final String PORT_MAPPINGS = "port-mappings";

	public static final String PORT_MAPPING = "port-mapping";

	public static final String CUSTOM_FILTER = "custom-filter";

	public static final String REQUEST_CACHE = "request-cache";

	public static final String X509 = "x509";

	public static final String JEE = "jee";

	public static final String FILTER_SECURITY_METADATA_SOURCE = "filter-security-metadata-source";

	public static final String METHOD_SECURITY_METADATA_SOURCE = "method-security-metadata-source";

	public static final String LDAP_PASSWORD_COMPARE = "password-compare";

	public static final String DEBUG = "debug";

	public static final String HTTP_FIREWALL = "http-firewall";

	public static final String HEADERS = "headers";

	public static final String CORS = "cors";

	public static final String CSRF = "csrf";

	public static final String OAUTH2_RESOURCE_SERVER = "oauth2-resource-server";

	public static final String JWT = "jwt";

	public static final String OPAQUE_TOKEN = "opaque-token";

	public static final String WEBSOCKET_MESSAGE_BROKER = "websocket-message-broker";

	public static final String INTERCEPT_MESSAGE = "intercept-message";

	public static final String OAUTH2_LOGIN = "oauth2-login";

	public static final String OAUTH2_CLIENT = "oauth2-client";

	public static final String CLIENT_REGISTRATIONS = "client-registrations";

	public static final String PASSWORD_MANAGEMENT = "password-management";

	public static final String RELYING_PARTY_REGISTRATIONS = "relying-party-registrations";

	public static final String SAML2_LOGIN = "saml2-login";

	public static final String SAML2_LOGOUT = "saml2-logout";

}
