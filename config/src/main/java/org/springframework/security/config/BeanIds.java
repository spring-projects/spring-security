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

    /** Package protected as end users shouldn't really be using this BFPP directly */
    static final String INTERCEPT_METHODS_BEAN_FACTORY_POST_PROCESSOR = "_interceptMethodsBeanfactoryPP";
    static final String CONTEXT_SOURCE_SETTING_POST_PROCESSOR = "_contextSettingPostProcessor";
//    static final String ENTRY_POINT_INJECTION_POST_PROCESSOR = "_entryPointInjectionBeanPostProcessor";
//    static final String USER_DETAILS_SERVICE_INJECTION_POST_PROCESSOR = "_userServiceInjectionPostProcessor";
//    static final String SESSION_REGISTRY_INJECTION_POST_PROCESSOR = "_sessionRegistryInjectionPostProcessor";
//    static final String FILTER_CHAIN_POST_PROCESSOR = "_filterChainProxyPostProcessor";
//    static final String FILTER_LIST = "_filterChainList";

//    public static final String JDBC_USER_DETAILS_MANAGER = "_jdbcUserDetailsManager";
    public static final String USER_DETAILS_SERVICE = "_userDetailsService";
//    public static final String ANONYMOUS_PROCESSING_FILTER = "_anonymousProcessingFilter";
    public static final String ANONYMOUS_AUTHENTICATION_PROVIDER = "_anonymousAuthenticationProvider";
//    public static final String BASIC_AUTHENTICATION_FILTER = "_basicAuthenticationFilter";
    public static final String BASIC_AUTHENTICATION_ENTRY_POINT = "_basicAuthenticationEntryPoint";
//    public static final String SESSION_REGISTRY = "_sessionRegistry";
//    public static final String CONCURRENT_SESSION_FILTER = "_concurrentSessionFilter";
    public static final String CONCURRENT_SESSION_CONTROLLER = "_concurrentSessionController";
    public static final String METHOD_ACCESS_MANAGER = "_defaultMethodAccessManager";
    public static final String WEB_ACCESS_MANAGER = "_webAccessManager";
    public static final String AUTHENTICATION_MANAGER = "_authenticationManager";
    public static final String AFTER_INVOCATION_MANAGER = "_afterInvocationManager";
    public static final String FORM_LOGIN_FILTER = "_formLoginFilter";
    public static final String FORM_LOGIN_ENTRY_POINT = "_formLoginEntryPoint";
    public static final String OPEN_ID_FILTER = "_openIDFilter";
    public static final String OPEN_ID_ENTRY_POINT = "_openIDFilterEntryPoint";
    public static final String OPEN_ID_PROVIDER = "_openIDAuthenticationProvider";
//    public static final String MAIN_ENTRY_POINT = "_mainEntryPoint";
    public static final String FILTER_CHAIN_PROXY = "_filterChainProxy";
//    public static final String SECURITY_CONTEXT_PERSISTENCE_FILTER = "_securityContextPersistenceFilter";
    public static final String LDAP_AUTHENTICATION_PROVIDER = "_ldapAuthenticationProvider";
//    public static final String LOGOUT_FILTER = "_logoutFilter";
//    public static final String EXCEPTION_TRANSLATION_FILTER = "_exceptionTranslationFilter";
//    public static final String FILTER_SECURITY_INTERCEPTOR = "_filterSecurityInterceptor";
//    public static final String CHANNEL_PROCESSING_FILTER = "_channelProcessingFilter";
    public static final String CHANNEL_DECISION_MANAGER = "_channelDecisionManager";
//    public static final String REMEMBER_ME_FILTER = "_rememberMeFilter";
//    public static final String REMEMBER_ME_SERVICES = "_rememberMeServices";
    public static final String REMEMBER_ME_AUTHENTICATION_PROVIDER = "_rememberMeAuthenticationProvider";
//    public static final String DEFAULT_LOGIN_PAGE_GENERATING_FILTER = "_defaultLoginPageFilter";
//    public static final String SECURITY_CONTEXT_HOLDER_AWARE_REQUEST_FILTER = "_securityContextHolderAwareRequestFilter";
    public static final String SESSION_FIXATION_PROTECTION_FILTER = "_sessionFixationProtectionFilter";
    public static final String METHOD_SECURITY_METADATA_SOURCE_ADVISOR = "_methodSecurityMetadataSourceAdvisor";
//    public static final String PROTECT_POINTCUT_POST_PROCESSOR = "_protectPointcutPostProcessor";
//    public static final String SECURED_METHOD_SECURITY_METADATA_SOURCE = "_securedSecurityMetadataSource";
//    public static final String JSR_250_METHOD_SECURITY_METADATA_SOURCE = "_jsr250SecurityMetadataSource";
    public static final String EMBEDDED_APACHE_DS = "_apacheDirectoryServerContainer";
    public static final String CONTEXT_SOURCE = "_securityContextSource";
//    public static final String PORT_MAPPER = "_portMapper";
//    public static final String X509_FILTER = "_x509ProcessingFilter";
    public static final String X509_AUTH_PROVIDER = "_x509AuthenticationProvider";
//    public static final String PRE_AUTH_ENTRY_POINT = "_preAuthenticatedProcessingFilterEntryPoint";
//    public static final String REMEMBER_ME_SERVICES_INJECTION_POST_PROCESSOR = "_rememberMeServicesInjectionBeanPostProcessor";
}
