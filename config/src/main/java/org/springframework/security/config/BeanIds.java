package org.springframework.security.config;

/**
 * Contains globally used default Bean IDs for beans created by the namespace support in Spring Security 2.
 * <p>
 * These are intended for internal use.
 *
 * @author Ben Alex
 */
public abstract class BeanIds {
    private static final String PREFIX = "org.springframework.security.";

    /** The "global" AuthenticationManager instance, registered by the <authentication-manager> element */
    public static final String AUTHENTICATION_MANAGER = PREFIX + "authenticationManager";

    /** External alias for FilterChainProxy bean, for use in web.xml files */
    public static final String SPRING_SECURITY_FILTER_CHAIN = "springSecurityFilterChain";

    public static final String CONTEXT_SOURCE_SETTING_POST_PROCESSOR = PREFIX + "contextSettingPostProcessor";

    public static final String USER_DETAILS_SERVICE = PREFIX + "userDetailsService";

    public static final String METHOD_ACCESS_MANAGER = PREFIX + "defaultMethodAccessManager";

    public static final String FILTER_CHAIN_PROXY = PREFIX + "filterChainProxy";

    public static final String METHOD_SECURITY_METADATA_SOURCE_ADVISOR = PREFIX + "methodSecurityMetadataSourceAdvisor";
    public static final String EMBEDDED_APACHE_DS = PREFIX + "apacheDirectoryServerContainer";
    public static final String CONTEXT_SOURCE = PREFIX + "securityContextSource";
}
