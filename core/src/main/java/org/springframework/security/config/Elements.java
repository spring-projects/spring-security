package org.springframework.security.config;

/**
 * Contains all the element names used by Spring Security 2 namespace support.
 *
 * @author Ben Alex
 * @version $Id$
 */
abstract class Elements {

	public static final String USER_SERVICE = "user-service";
	public static final String JDBC_USER_SERVICE = "jdbc-user-service";
	public static final String FILTER_CHAIN_MAP = "filter-chain-map";
	public static final String INTERCEPT_METHODS = "intercept-methods";
	public static final String AUTHENTICATION_PROVIDER = "authentication-provider";
	public static final String HTTP = "http";
	public static final String LDAP_PROVIDER = "ldap-authentication-provider";
	public static final String LDAP_SERVER = "ldap-server";
    public static final String PROTECT = "protect";
	public static final String CONCURRENT_SESSIONS = "concurrent-session-control";
	public static final String LOGOUT = "logout";
	public static final String FORM_LOGIN = "form-login";
	public static final String BASIC_AUTH = "http-basic";
	public static final String REMEMBER_ME = "remember-me";
	public static final String ANONYMOUS = "anonymous";
	public static final String FILTER_CHAIN = "filter-chain";
	public static final String ANNOTATION_DRIVEN = "annotation-driven";
	public static final String PASSWORD_ENCODER = "password-encoder";
	public static final String SALT_SOURCE = "salt-source";
	public static final String PORT_MAPPINGS = "port-mappings";
    public static final String PORT_MAPPING = "port-mapping";
    public static final String CUSTOM_FILTER = "custom-filter";    
}
