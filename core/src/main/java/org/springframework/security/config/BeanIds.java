package org.springframework.security.config;

/**
 * Contains all the default Bean IDs created by the namespace support in Spring Security 2.
 * 
 * @author Ben Alex
 * @version $Id$
 */
public class BeanIds {

	/** Package protected as end users shouldn't really be using this BFPP directly */
	static final String INTERCEPT_METHODS_BEAN_FACTORY_POST_PROCESSOR = "_interceptMethodsBeanfactoryPP";

	public static final String JDBC_USER_DETAILS_MANAGER = "_jdbcUserDetailsManager";
	public static final String USER_DETAILS_SERVICE = "_userDetailsService";
	public static final String ANONYMOUS_PROCESSING_FILTER = "_anonymousProcessingFilter";
	public static final String ANONYMOUS_AUTHENTICATION_PROVIDER = "_anonymousAuthenticationProvider";
	public static final String BASIC_AUTHENTICATION_FILTER = "_basicAuthenticationFilter";
	public static final String BASIC_AUTHENTICATION_ENTRY_POINT = "_basicAuthenticationEntryPoint";
	public static final String SESSION_REGISTRY = "_sessionRegistry";
	public static final String CONCURRENT_SESSION_FILTER = "_concurrentSessionFilter";
	public static final String CONCURRENT_SESSION_CONTROLLER = "_concurrentSessionController";
	public static final String ACCESS_MANAGER = "_accessManager";
	public static final String AUTHENTICATION_MANAGER = "_authenticationManager";
	public static final String FORM_LOGIN_FILTER = "_formLoginFilter";
	public static final String FORM_LOGIN_ENTRY_POINT = "_formLoginEntryPoint";
	public static final String FILTER_CHAIN_PROXY = "_filterChainProxy";
	public static final String HTTP_SESSION_CONTEXT_INTEGRATION_FILTER = "_httpSessionContextIntegrationFilter";
	public static final String LOGOUT_FILTER = "_logoutFilter";
	public static final String EXCEPTION_TRANSLATION_FILTER = "_exceptionTranslationFilter";
	public static final String FILTER_SECURITY_INTERCEPTOR = "_filterSecurityInterceptor";
	public static final String CHANNEL_PROCESSING_FILTER = "_channelProcessingFilter";
	public static final String CHANNEL_DECISION_MANAGER = "_channelDecisionManager";
	public static final String REMEMBER_ME_FILTER = "_rememberMeFilter";
	public static final String REMEMBER_ME_SERVICES = "_rememberMeServices";
	public static final String DEFAULT_LOGIN_PAGE_GENERATING_FILTER = "_defaultLoginPageFilter";

	
	
}
