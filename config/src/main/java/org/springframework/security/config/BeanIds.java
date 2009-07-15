package org.springframework.security.config;

/**
 * Contains globally used default Bean IDs for beans created by the namespace support in Spring Security 2.
 * <p>
 * These are intended for internal use.
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class BeanIds {

    /** External alias for FilterChainProxy bean, for use in web.xml files */
    public static final String SPRING_SECURITY_FILTER_CHAIN = "springSecurityFilterChain";

    static final String CONTEXT_SOURCE_SETTING_POST_PROCESSOR = "_contextSettingPostProcessor";

    public static final String USER_DETAILS_SERVICE = "_userDetailsService";

    public static final String METHOD_ACCESS_MANAGER = "_defaultMethodAccessManager";
    public static final String WEB_ACCESS_MANAGER = "_webAccessManager";
    public static final String AUTHENTICATION_MANAGER = "_authenticationManager";
    public static final String AFTER_INVOCATION_MANAGER = "_afterInvocationManager";
    public static final String FORM_LOGIN_FILTER = "_formLoginFilter";
    public static final String FORM_LOGIN_ENTRY_POINT = "_formLoginEntryPoint";
    public static final String OPEN_ID_FILTER = "_openIDFilter";
    public static final String OPEN_ID_ENTRY_POINT = "_openIDFilterEntryPoint";

    public static final String FILTER_CHAIN_PROXY = "_filterChainProxy";
    public static final String LDAP_AUTHENTICATION_PROVIDER = "_ldapAuthenticationProvider";

    public static final String SESSION_FIXATION_PROTECTION_FILTER = "_sessionFixationProtectionFilter";
    public static final String METHOD_SECURITY_METADATA_SOURCE_ADVISOR = "_methodSecurityMetadataSourceAdvisor";
    public static final String EMBEDDED_APACHE_DS = "_apacheDirectoryServerContainer";
    public static final String CONTEXT_SOURCE = "_securityContextSource";
}
