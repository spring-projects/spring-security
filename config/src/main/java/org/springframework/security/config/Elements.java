package org.springframework.security.config;

/**
 * Contains all the element names used by Spring Security 2 namespace support.
 *
 * @author Ben Alex
 * @version $Id: Elements.java 3697 2009-06-08 12:59:13Z ltaylor $
 */
public abstract class Elements {

    public static final String ACCESS_DENIED_HANDLER = "access-denied-handler";
    public static final String AUTHENTICATION_MANAGER = "authentication-manager";
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
    public static final String CONCURRENT_SESSIONS = "concurrent-session-control";
    public static final String LOGOUT = "logout";
    public static final String FORM_LOGIN = "form-login";
    public static final String OPENID_LOGIN = "openid-login";
    public static final String BASIC_AUTH = "http-basic";
    public static final String REMEMBER_ME = "remember-me";
    public static final String ANONYMOUS = "anonymous";
    public static final String FILTER_CHAIN = "filter-chain";
    public static final String GLOBAL_METHOD_SECURITY = "global-method-security";
    public static final String PASSWORD_ENCODER = "password-encoder";
    public static final String SALT_SOURCE = "salt-source";
    public static final String PORT_MAPPINGS = "port-mappings";
    public static final String PORT_MAPPING = "port-mapping";
    public static final String CUSTOM_FILTER = "custom-filter";
    @Deprecated
    public static final String CUSTOM_AUTH_PROVIDER = "custom-authentication-provider";
    public static final String CUSTOM_AFTER_INVOCATION_PROVIDER = "custom-after-invocation-provider";
    public static final String X509 = "x509";
    public static final String FILTER_SECURITY_METADATA_SOURCE = "filter-security-metadata-source";
    @Deprecated
    public static final String FILTER_INVOCATION_DEFINITION_SOURCE = "filter-invocation-definition-source";
    public static final String LDAP_PASSWORD_COMPARE = "password-compare";
}
