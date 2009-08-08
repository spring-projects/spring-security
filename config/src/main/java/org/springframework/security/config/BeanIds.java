package org.springframework.security.config;

/**
 * Contains globally used default Bean IDs for beans created by the namespace support in Spring Security 2.
 * <p>
 * These are intended for internal use.
 *
 * @author Ben Alex
 * @version $Id: BeanIds.java 3770 2009-07-15 23:09:47Z ltaylor $
 */
public abstract class BeanIds {

    /** External alias for FilterChainProxy bean, for use in web.xml files */
    public static final String SPRING_SECURITY_FILTER_CHAIN = "springSecurityFilterChain";

    public static final String CONTEXT_SOURCE_SETTING_POST_PROCESSOR = "_contextSettingPostProcessor";

    public static final String USER_DETAILS_SERVICE = "_userDetailsService";

    public static final String METHOD_ACCESS_MANAGER = "_defaultMethodAccessManager";
    public static final String AUTHENTICATION_MANAGER = "_authenticationManager";

    public static final String FILTER_CHAIN_PROXY = "_filterChainProxy";

    public static final String METHOD_SECURITY_METADATA_SOURCE_ADVISOR = "_methodSecurityMetadataSourceAdvisor";
    public static final String EMBEDDED_APACHE_DS = "_apacheDirectoryServerContainer";
    public static final String CONTEXT_SOURCE = "_securityContextSource";
}
