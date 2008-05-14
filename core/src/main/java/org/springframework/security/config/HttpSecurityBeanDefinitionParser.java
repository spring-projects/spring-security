package org.springframework.security.config;

import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.ConfigAttributeEditor;
import org.springframework.security.wrapper.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.intercept.web.DefaultFilterInvocationDefinitionSource;
import org.springframework.security.intercept.web.FilterSecurityInterceptor;
import org.springframework.security.intercept.web.RequestKey;
import org.springframework.security.securechannel.ChannelDecisionManagerImpl;
import org.springframework.security.securechannel.ChannelProcessingFilter;
import org.springframework.security.securechannel.InsecureChannelProcessor;
import org.springframework.security.securechannel.SecureChannelProcessor;
import org.springframework.security.securechannel.RetryWithHttpEntryPoint;
import org.springframework.security.securechannel.RetryWithHttpsEntryPoint;
import org.springframework.security.ui.AccessDeniedHandlerImpl;
import org.springframework.security.ui.ExceptionTranslationFilter;
import org.springframework.security.ui.SessionFixationProtectionFilter;
import org.springframework.security.ui.webapp.DefaultLoginPageGeneratingFilter;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.security.util.RegexUrlPathMatcher;
import org.springframework.security.util.AntUrlPathMatcher;
import org.springframework.security.util.UrlMatcher;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Sets up HTTP security: filter stack and protected URLs.
 *
 * @author Luke Taylor
 * @author Ben Alex
 * @since 2.0
 * @version $Id$
 */
public class HttpSecurityBeanDefinitionParser implements BeanDefinitionParser {
	protected final Log logger = LogFactory.getLog(getClass());

    static final String ATT_REALM = "realm";
    static final String DEF_REALM = "Spring Security Application";

    static final String ATT_PATH_PATTERN = "pattern";
    
    static final String ATT_SESSION_FIXATION_PROTECTION = "session-fixation-protection";
    static final String OPT_SESSION_FIXATION_NO_PROTECTION = "none";
    static final String OPT_SESSION_FIXATION_CLEAN_SESSION = "newSession";    
    static final String OPT_SESSION_FIXATION_MIGRATE_SESSION = "migrateSession";

    static final String ATT_PATH_TYPE = "path-type";
    static final String DEF_PATH_TYPE_ANT = "ant";
    static final String OPT_PATH_TYPE_REGEX = "regex";

    static final String ATT_FILTERS = "filters";
    static final String OPT_FILTERS_NONE = "none";

    static final String ATT_ACCESS_CONFIG = "access";
    static final String ATT_REQUIRES_CHANNEL = "requires-channel";
    static final String OPT_REQUIRES_HTTP = "http";
    static final String OPT_REQUIRES_HTTPS = "https";
    static final String OPT_ANY_CHANNEL = "any";

    static final String ATT_HTTP_METHOD = "method";

    static final String ATT_CREATE_SESSION = "create-session";
    static final String DEF_CREATE_SESSION_IF_REQUIRED = "ifRequired";
    static final String OPT_CREATE_SESSION_ALWAYS = "always";
    static final String OPT_CREATE_SESSION_NEVER = "never";

    static final String ATT_LOWERCASE_COMPARISONS = "lowercase-comparisons";
    static final String DEF_LOWERCASE_COMPARISONS = "true";

    static final String ATT_AUTO_CONFIG = "auto-config";
    static final String DEF_AUTO_CONFIG = "false";

    static final String ATT_SERVLET_API_PROVISION = "servlet-api-provision";
    static final String DEF_SERVLET_API_PROVISION = "true";

    static final String ATT_ACCESS_MGR = "access-decision-manager-ref";    
    static final String ATT_USER_SERVICE_REF = "user-service-ref";
    
    static final String ATT_ENTRY_POINT_REF = "entry-point-ref";
    static final String ATT_ONCE_PER_REQUEST = "once-per-request";
    static final String ATT_ACCESS_DENIED_PAGE = "access-denied-page";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        ConfigUtils.registerProviderManagerIfNecessary(parserContext);
        final BeanDefinitionRegistry registry = parserContext.getRegistry();
        final UrlMatcher matcher = createUrlMatcher(element);
        final Object source = parserContext.extractSource(element);
        // SEC-501 - should paths stored in request maps be converted to lower case
        // true if Ant path and using lower case
        final boolean convertPathsToLowerCase = (matcher instanceof AntUrlPathMatcher) && matcher.requiresLowerCaseUrl();
        
        final List interceptUrlElts = DomUtils.getChildElementsByTagName(element, Elements.INTERCEPT_URL);
        final Map filterChainMap =  new LinkedHashMap();
        final LinkedHashMap channelRequestMap = new LinkedHashMap();

        registerFilterChainProxy(parserContext, filterChainMap, matcher, source);
        
        parseInterceptUrlsForChannelSecurityAndFilterChain(interceptUrlElts, filterChainMap, channelRequestMap, 
                convertPathsToLowerCase, parserContext);

        registerHttpSessionIntegrationFilter(element, parserContext);
        
        registerServletApiFilter(element, parserContext);
                
        // Set up the access manager reference for http
        String accessManagerId = element.getAttribute(ATT_ACCESS_MGR);

        if (!StringUtils.hasText(accessManagerId)) {
            ConfigUtils.registerDefaultAccessManagerIfNecessary(parserContext);
            accessManagerId = BeanIds.ACCESS_MANAGER;
        }
        
        // Register the portMapper. A default will always be created, even if no element exists.
        BeanDefinition portMapper = new PortMappingsBeanDefinitionParser().parse(
                DomUtils.getChildElementByTagName(element, Elements.PORT_MAPPINGS), parserContext);
        registry.registerBeanDefinition(BeanIds.PORT_MAPPER, portMapper);

        registerExceptionTranslationFilter(element, parserContext);


        if (channelRequestMap.size() > 0) {
            // At least one channel requirement has been specified
            registerChannelProcessingBeans(parserContext, matcher, channelRequestMap);
        }        
                
        registerFilterSecurityInterceptor(element, parserContext, matcher, accessManagerId, 
                parseInterceptUrlsForFilterInvocationRequestMap(interceptUrlElts, convertPathsToLowerCase, parserContext));

        boolean sessionControlEnabled = registerConcurrentSessionControlBeansIfRequired(element, parserContext);
        
        registerSessionFixationProtectionFilter(parserContext, element.getAttribute(ATT_SESSION_FIXATION_PROTECTION), 
                sessionControlEnabled);

        boolean autoConfig = false;
        if ("true".equals(element.getAttribute(ATT_AUTO_CONFIG))) {
        	autoConfig = true;
        }

        Element anonymousElt = DomUtils.getChildElementByTagName(element, Elements.ANONYMOUS);
        if (anonymousElt != null || autoConfig) {
            new AnonymousBeanDefinitionParser().parse(anonymousElt, parserContext);
        }

        // Parse remember me before logout as RememberMeServices is also a LogoutHandler implementation.
        Element rememberMeElt = DomUtils.getChildElementByTagName(element, Elements.REMEMBER_ME);
        if (rememberMeElt != null || autoConfig) {
            new RememberMeBeanDefinitionParser().parse(rememberMeElt, parserContext);
            // Post processor to inject RememberMeServices into filters which need it
            RootBeanDefinition rememberMeInjectionPostProcessor = new RootBeanDefinition(RememberMeServicesInjectionBeanPostProcessor.class);
            rememberMeInjectionPostProcessor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
            registry.registerBeanDefinition(BeanIds.REMEMBER_ME_SERVICES_INJECTION_POST_PROCESSOR, rememberMeInjectionPostProcessor);            
        }
        
        Element logoutElt = DomUtils.getChildElementByTagName(element, Elements.LOGOUT);
        if (logoutElt != null || autoConfig) {
            new LogoutBeanDefinitionParser().parse(logoutElt, parserContext);
        }
        
        parseBasicFormLoginAndOpenID(element, parserContext, autoConfig);

        Element x509Elt = DomUtils.getChildElementByTagName(element, Elements.X509);
        if (x509Elt != null) {
            new X509BeanDefinitionParser().parse(x509Elt, parserContext);
        }

        // Register the post processors which will tie up the loose ends in the configuration once the app context has been created and all beans are available.
        RootBeanDefinition postProcessor = new RootBeanDefinition(EntryPointInjectionBeanPostProcessor.class);
        postProcessor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        registry.registerBeanDefinition(BeanIds.ENTRY_POINT_INJECTION_POST_PROCESSOR, postProcessor);
        RootBeanDefinition postProcessor2 = new RootBeanDefinition(UserDetailsServiceInjectionBeanPostProcessor.class);
        postProcessor2.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        registry.registerBeanDefinition(BeanIds.USER_DETAILS_SERVICE_INJECTION_POST_PROCESSOR, postProcessor2);
        
        return null;
    }
    
    private void registerFilterChainProxy(ParserContext pc, Map filterChainMap, UrlMatcher matcher, Object source) {
        if (pc.getRegistry().containsBeanDefinition(BeanIds.FILTER_CHAIN_PROXY)) {
            pc.getReaderContext().error("Duplicate <http> element detected", source);
        }
        
        RootBeanDefinition filterChainProxy = new RootBeanDefinition(FilterChainProxy.class);
        filterChainProxy.setSource(source);
        filterChainProxy.getPropertyValues().addPropertyValue("matcher", matcher);
        filterChainProxy.getPropertyValues().addPropertyValue("filterChainMap", filterChainMap);
        pc.getRegistry().registerBeanDefinition(BeanIds.FILTER_CHAIN_PROXY, filterChainProxy);
        pc.getRegistry().registerAlias(BeanIds.FILTER_CHAIN_PROXY, BeanIds.SPRING_SECURITY_FILTER_CHAIN);        
    }

    private void registerHttpSessionIntegrationFilter(Element element, ParserContext pc) {
        RootBeanDefinition httpScif = new RootBeanDefinition(HttpSessionContextIntegrationFilter.class);
        
        String createSession = element.getAttribute(ATT_CREATE_SESSION);
        if (OPT_CREATE_SESSION_ALWAYS.equals(createSession)) {
            httpScif.getPropertyValues().addPropertyValue("allowSessionCreation", Boolean.TRUE);
            httpScif.getPropertyValues().addPropertyValue("forceEagerSessionCreation", Boolean.TRUE);
        } else if (OPT_CREATE_SESSION_NEVER.equals(createSession)) {
            httpScif.getPropertyValues().addPropertyValue("allowSessionCreation", Boolean.FALSE);
            httpScif.getPropertyValues().addPropertyValue("forceEagerSessionCreation", Boolean.FALSE);
        } else {
            createSession = DEF_CREATE_SESSION_IF_REQUIRED;
            httpScif.getPropertyValues().addPropertyValue("allowSessionCreation", Boolean.TRUE);
            httpScif.getPropertyValues().addPropertyValue("forceEagerSessionCreation", Boolean.FALSE);
        }

        pc.getRegistry().registerBeanDefinition(BeanIds.HTTP_SESSION_CONTEXT_INTEGRATION_FILTER, httpScif);
        ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.HTTP_SESSION_CONTEXT_INTEGRATION_FILTER));
    }

    // Adds the servlet-api integration filter if required    
    private void registerServletApiFilter(Element element, ParserContext pc) {
        String provideServletApi = element.getAttribute(ATT_SERVLET_API_PROVISION);
        if (!StringUtils.hasText(provideServletApi)) {
            provideServletApi = DEF_SERVLET_API_PROVISION;
        }

        if ("true".equals(provideServletApi)) {
            pc.getRegistry().registerBeanDefinition(BeanIds.SECURITY_CONTEXT_HOLDER_AWARE_REQUEST_FILTER,
                    new RootBeanDefinition(SecurityContextHolderAwareRequestFilter.class));
            ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.SECURITY_CONTEXT_HOLDER_AWARE_REQUEST_FILTER));
        }
    }
    
    private boolean registerConcurrentSessionControlBeansIfRequired(Element element, ParserContext parserContext) {
        Element sessionControlElt = DomUtils.getChildElementByTagName(element, Elements.CONCURRENT_SESSIONS);
        if (sessionControlElt == null) {
            return false;
        }
        
        new ConcurrentSessionsBeanDefinitionParser().parse(sessionControlElt, parserContext);
        logger.info("Concurrent session filter in use, setting 'forceEagerSessionCreation' to true");
        BeanDefinition sessionIntegrationFilter = parserContext.getRegistry().getBeanDefinition(BeanIds.HTTP_SESSION_CONTEXT_INTEGRATION_FILTER); 
        sessionIntegrationFilter.getPropertyValues().addPropertyValue("forceEagerSessionCreation", Boolean.TRUE);
        return true;
    }
    
    private void registerExceptionTranslationFilter(Element element, ParserContext pc) {
    	String accessDeniedPage = element.getAttribute(ATT_ACCESS_DENIED_PAGE);
    	ConfigUtils.validateHttpRedirect(accessDeniedPage, pc, pc.extractSource(element));
        BeanDefinitionBuilder exceptionTranslationFilterBuilder
            = BeanDefinitionBuilder.rootBeanDefinition(ExceptionTranslationFilter.class);
 
        if (StringUtils.hasText(accessDeniedPage)) {
            AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
            accessDeniedHandler.setErrorPage(accessDeniedPage);
            exceptionTranslationFilterBuilder.addPropertyValue("accessDeniedHandler", accessDeniedHandler);
        }

        pc.getRegistry().registerBeanDefinition(BeanIds.EXCEPTION_TRANSLATION_FILTER, exceptionTranslationFilterBuilder.getBeanDefinition());
        ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.EXCEPTION_TRANSLATION_FILTER));
    }
    
    private void registerFilterSecurityInterceptor(Element element, ParserContext pc, UrlMatcher matcher,
            String accessManagerId, LinkedHashMap filterInvocationDefinitionMap) {
        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(FilterSecurityInterceptor.class);

        builder.addPropertyReference("accessDecisionManager", accessManagerId);
        builder.addPropertyReference("authenticationManager", BeanIds.AUTHENTICATION_MANAGER);
        
        if ("false".equals(element.getAttribute(ATT_ONCE_PER_REQUEST))) {
            builder.addPropertyValue("observeOncePerRequest", Boolean.FALSE);
        }
        
        DefaultFilterInvocationDefinitionSource fids = 
            new DefaultFilterInvocationDefinitionSource(matcher, filterInvocationDefinitionMap);
        fids.setStripQueryStringFromUrls(matcher instanceof AntUrlPathMatcher);
        
        builder.addPropertyValue("objectDefinitionSource", fids);
        pc.getRegistry().registerBeanDefinition(BeanIds.FILTER_SECURITY_INTERCEPTOR, builder.getBeanDefinition());
        ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.FILTER_SECURITY_INTERCEPTOR));
    }
    
    private void registerChannelProcessingBeans(ParserContext pc, UrlMatcher matcher, LinkedHashMap channelRequestMap) {
        RootBeanDefinition channelFilter = new RootBeanDefinition(ChannelProcessingFilter.class);
        channelFilter.getPropertyValues().addPropertyValue("channelDecisionManager",
                new RuntimeBeanReference(BeanIds.CHANNEL_DECISION_MANAGER));
        DefaultFilterInvocationDefinitionSource channelFilterInvDefSource =
            new DefaultFilterInvocationDefinitionSource(matcher, channelRequestMap);
        channelFilterInvDefSource.setStripQueryStringFromUrls(matcher instanceof AntUrlPathMatcher);
        
        channelFilter.getPropertyValues().addPropertyValue("filterInvocationDefinitionSource",
                channelFilterInvDefSource);
        RootBeanDefinition channelDecisionManager = new RootBeanDefinition(ChannelDecisionManagerImpl.class);
        ManagedList channelProcessors = new ManagedList(3);
        RootBeanDefinition secureChannelProcessor = new RootBeanDefinition(SecureChannelProcessor.class);
        RootBeanDefinition retryWithHttp = new RootBeanDefinition(RetryWithHttpEntryPoint.class);
        RootBeanDefinition retryWithHttps = new RootBeanDefinition(RetryWithHttpsEntryPoint.class);
        RuntimeBeanReference portMapper = new RuntimeBeanReference(BeanIds.PORT_MAPPER);
        retryWithHttp.getPropertyValues().addPropertyValue("portMapper", portMapper);
        retryWithHttps.getPropertyValues().addPropertyValue("portMapper", portMapper);
        secureChannelProcessor.getPropertyValues().addPropertyValue("entryPoint", retryWithHttps);
        RootBeanDefinition inSecureChannelProcessor = new RootBeanDefinition(InsecureChannelProcessor.class);
        inSecureChannelProcessor.getPropertyValues().addPropertyValue("entryPoint", retryWithHttp);
        channelProcessors.add(secureChannelProcessor);
        channelProcessors.add(inSecureChannelProcessor);
        channelDecisionManager.getPropertyValues().addPropertyValue("channelProcessors", channelProcessors);

        pc.getRegistry().registerBeanDefinition(BeanIds.CHANNEL_PROCESSING_FILTER, channelFilter);
        ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.CHANNEL_PROCESSING_FILTER));
        pc.getRegistry().registerBeanDefinition(BeanIds.CHANNEL_DECISION_MANAGER, channelDecisionManager);
        
    }
    
    private void registerSessionFixationProtectionFilter(ParserContext pc, String sessionFixationAttribute, boolean sessionControlEnabled) {
        if(!StringUtils.hasText(sessionFixationAttribute)) {
            sessionFixationAttribute = OPT_SESSION_FIXATION_MIGRATE_SESSION;
        }
        
        if (!sessionFixationAttribute.equals(OPT_SESSION_FIXATION_NO_PROTECTION)) {
            BeanDefinitionBuilder sessionFixationFilter = 
                BeanDefinitionBuilder.rootBeanDefinition(SessionFixationProtectionFilter.class);
            sessionFixationFilter.addPropertyValue("migrateSessionAttributes", 
                    Boolean.valueOf(sessionFixationAttribute.equals(OPT_SESSION_FIXATION_MIGRATE_SESSION)));
            if (sessionControlEnabled) {
                sessionFixationFilter.addPropertyReference("sessionRegistry", BeanIds.SESSION_REGISTRY);
            }
            pc.getRegistry().registerBeanDefinition(BeanIds.SESSION_FIXATION_PROTECTION_FILTER, 
                    sessionFixationFilter.getBeanDefinition());
            ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.SESSION_FIXATION_PROTECTION_FILTER));
        }
    }
    
    private void parseBasicFormLoginAndOpenID(Element element, ParserContext pc, boolean autoConfig) {
        RootBeanDefinition formLoginFilter = null;
        RootBeanDefinition formLoginEntryPoint = null;
        String formLoginPage = null;        
        RootBeanDefinition openIDFilter = null;
        RootBeanDefinition openIDEntryPoint = null;
        String openIDLoginPage = null;
    	
        String realm = element.getAttribute(ATT_REALM);
        if (!StringUtils.hasText(realm)) {
        	realm = DEF_REALM;
        }
        
        Element basicAuthElt = DomUtils.getChildElementByTagName(element, Elements.BASIC_AUTH);
        if (basicAuthElt != null || autoConfig) {
            new BasicAuthenticationBeanDefinitionParser(realm).parse(basicAuthElt, pc);
        }
        
    	Element formLoginElt = DomUtils.getChildElementByTagName(element, Elements.FORM_LOGIN);
        
        if (formLoginElt != null || autoConfig) {
        	FormLoginBeanDefinitionParser parser = new FormLoginBeanDefinitionParser("/j_spring_security_check", 
        			"org.springframework.security.ui.webapp.AuthenticationProcessingFilter");
        	
            parser.parse(formLoginElt, pc);
            formLoginFilter = parser.getFilterBean();
            formLoginEntryPoint = parser.getEntryPointBean();
            formLoginPage = parser.getLoginPage();
        }
        
        Element openIDLoginElt = DomUtils.getChildElementByTagName(element, Elements.OPENID_LOGIN);

        if (openIDLoginElt != null) {
        	FormLoginBeanDefinitionParser parser = new FormLoginBeanDefinitionParser("/j_spring_openid_security_check", 
        			"org.springframework.security.ui.openid.OpenIDAuthenticationProcessingFilter");
        	
            parser.parse(openIDLoginElt, pc);
            openIDFilter = parser.getFilterBean();
            openIDEntryPoint = parser.getEntryPointBean();
            openIDLoginPage = parser.getLoginPage();
            
            BeanDefinitionBuilder openIDProviderBuilder = 
                BeanDefinitionBuilder.rootBeanDefinition("org.springframework.security.providers.openid.OpenIDAuthenticationProvider");
            
            String userService = openIDLoginElt.getAttribute(ATT_USER_SERVICE_REF);
            
            if (StringUtils.hasText(userService)) {
                openIDProviderBuilder.addPropertyReference("userDetailsService", userService);
            }
            
            BeanDefinition openIDProvider = openIDProviderBuilder.getBeanDefinition();
            ConfigUtils.getRegisteredProviders(pc).add(openIDProvider);
            
            pc.getRegistry().registerBeanDefinition(BeanIds.OPEN_ID_PROVIDER, openIDProvider);
        }
        
        boolean needLoginPage = false;
        
        if (formLoginFilter != null) {
        	needLoginPage = true;
	        pc.getRegistry().registerBeanDefinition(BeanIds.FORM_LOGIN_FILTER, formLoginFilter);
	        ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.FORM_LOGIN_FILTER));
	        pc.getRegistry().registerBeanDefinition(BeanIds.FORM_LOGIN_ENTRY_POINT, formLoginEntryPoint);
        }        

        if (openIDFilter != null) {
        	needLoginPage = true;
	        pc.getRegistry().registerBeanDefinition(BeanIds.OPEN_ID_FILTER, openIDFilter);
	        ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.OPEN_ID_FILTER));
	        pc.getRegistry().registerBeanDefinition(BeanIds.OPEN_ID_ENTRY_POINT, openIDEntryPoint);
        }

        // If no login page has been defined, add in the default page generator.
        if (needLoginPage && formLoginPage == null && openIDLoginPage == null) {
            logger.info("No login page configured. The default internal one will be used. Use the '"
                     + FormLoginBeanDefinitionParser.ATT_LOGIN_PAGE + "' attribute to set the URL of the login page.");
            BeanDefinitionBuilder loginPageFilter = 
            	BeanDefinitionBuilder.rootBeanDefinition(DefaultLoginPageGeneratingFilter.class);
            
            if (formLoginFilter != null) {
            	loginPageFilter.addConstructorArg(new RuntimeBeanReference(BeanIds.FORM_LOGIN_FILTER));
            }
            
            if (openIDFilter != null) {
            	loginPageFilter.addConstructorArg(new RuntimeBeanReference(BeanIds.OPEN_ID_FILTER));
            }

            pc.getRegistry().registerBeanDefinition(BeanIds.DEFAULT_LOGIN_PAGE_GENERATING_FILTER, 
            		loginPageFilter.getBeanDefinition());
            ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.DEFAULT_LOGIN_PAGE_GENERATING_FILTER));
        }
        
        // We need to establish the main entry point.
        // First check if a custom entry point bean is set
        String customEntryPoint = element.getAttribute(ATT_ENTRY_POINT_REF);
        
        if (StringUtils.hasText(customEntryPoint)) {
            pc.getRegistry().registerAlias(customEntryPoint, BeanIds.MAIN_ENTRY_POINT);
            return;
        }
        
        // Basic takes precedence if explicit element is used and no others are configured
        if (basicAuthElt != null && formLoginElt == null && openIDLoginElt == null) {
        	pc.getRegistry().registerAlias(BeanIds.BASIC_AUTHENTICATION_ENTRY_POINT, BeanIds.MAIN_ENTRY_POINT);
        	return;
        }
        
        // If formLogin has been enabled either through an element or auto-config, then it is used if no openID login page
        // has been set
        if (formLoginFilter != null && openIDLoginPage == null) {
        	pc.getRegistry().registerAlias(BeanIds.FORM_LOGIN_ENTRY_POINT, BeanIds.MAIN_ENTRY_POINT);
        	return;        	
        }
        
        // Otherwise use OpenID if enabled
        if (openIDFilter != null && formLoginFilter == null) {
        	pc.getRegistry().registerAlias(BeanIds.OPEN_ID_ENTRY_POINT, BeanIds.MAIN_ENTRY_POINT);
        	return;        	
        }
        
        // If X.509 has been enabled, use the preauth entry point.
        if (DomUtils.getChildElementByTagName(element, Elements.X509) != null) {
            pc.getRegistry().registerAlias(BeanIds.PRE_AUTH_ENTRY_POINT, BeanIds.MAIN_ENTRY_POINT);
            return;
        }
        
        pc.getReaderContext().error("No AuthenticationEntryPoint could be established. Please " +
        		"make sure you have a login mechanism configured through the namespace (such as form-login) or " +
        		"specify a custom AuthenticationEntryPoint with the custom-entry-point-ref attribute ", 
                pc.extractSource(element));
    }
    
    static UrlMatcher createUrlMatcher(Element element) {
        String patternType = element.getAttribute(ATT_PATH_TYPE);
        if (!StringUtils.hasText(patternType)) {
            patternType = DEF_PATH_TYPE_ANT;
        }

        boolean useRegex = patternType.equals(OPT_PATH_TYPE_REGEX);

        UrlMatcher matcher = new AntUrlPathMatcher();

        if (useRegex) {
            matcher = new RegexUrlPathMatcher();
        }

        // Deal with lowercase conversion requests
        String lowercaseComparisons = element.getAttribute(ATT_LOWERCASE_COMPARISONS);
        if (!StringUtils.hasText(lowercaseComparisons)) {
            lowercaseComparisons = null;
        }


        // Only change from the defaults if the attribute has been set
        if ("true".equals(lowercaseComparisons)) {
            if (useRegex) {
                ((RegexUrlPathMatcher)matcher).setRequiresLowerCaseUrl(true);
            }
            // Default for ant is already to force lower case
        } else if ("false".equals(lowercaseComparisons)) {
            if (!useRegex) {
                ((AntUrlPathMatcher)matcher).setRequiresLowerCaseUrl(false);
            }
            // Default for regex is no change
        }
        
        return matcher;        
    }

    /**
     * Parses the intercept-url elements and populates the FilterChainProxy's filter chain Map and the
     * map used to create the FilterInvocationDefintionSource for the FilterSecurityInterceptor.
     */
    void parseInterceptUrlsForChannelSecurityAndFilterChain(List urlElts, Map filterChainMap,  Map channelRequestMap,
            boolean useLowerCasePaths, ParserContext parserContext) {

        Iterator urlEltsIterator = urlElts.iterator();
        ConfigAttributeEditor editor = new ConfigAttributeEditor();

        while (urlEltsIterator.hasNext()) {
            Element urlElt = (Element) urlEltsIterator.next();

            String path = urlElt.getAttribute(ATT_PATH_PATTERN);

            if(!StringUtils.hasText(path)) {
                parserContext.getReaderContext().error("path attribute cannot be empty or null", urlElt);
            }

            if (useLowerCasePaths) {
                path = path.toLowerCase();
            }

            String requiredChannel = urlElt.getAttribute(ATT_REQUIRES_CHANNEL);

            if (StringUtils.hasText(requiredChannel)) {
                String channelConfigAttribute = null;

                if (requiredChannel.equals(OPT_REQUIRES_HTTPS)) {
                    channelConfigAttribute = "REQUIRES_SECURE_CHANNEL";
                } else if (requiredChannel.equals(OPT_REQUIRES_HTTP)) {
                    channelConfigAttribute = "REQUIRES_INSECURE_CHANNEL";
                } else if (requiredChannel.equals(OPT_ANY_CHANNEL)) {
                    channelConfigAttribute = ChannelDecisionManagerImpl.ANY_CHANNEL;
                } else {
                    parserContext.getReaderContext().error("Unsupported channel " + requiredChannel, urlElt);
                }

                editor.setAsText(channelConfigAttribute);
                channelRequestMap.put(new RequestKey(path), (ConfigAttributeDefinition) editor.getValue());
            }
            
            String filters = urlElt.getAttribute(ATT_FILTERS);

            if (StringUtils.hasText(filters)) {
                if (!filters.equals(OPT_FILTERS_NONE)) {
                    parserContext.getReaderContext().error("Currently only 'none' is supported as the custom " +
                            "filters attribute", urlElt);
                }

                filterChainMap.put(path, Collections.EMPTY_LIST);
            }
        }
    }
    
    static LinkedHashMap parseInterceptUrlsForFilterInvocationRequestMap(List urlElts,  boolean useLowerCasePaths, ParserContext parserContext) {
        LinkedHashMap filterInvocationDefinitionMap = new LinkedHashMap();
        
        Iterator urlEltsIterator = urlElts.iterator();
        ConfigAttributeEditor editor = new ConfigAttributeEditor();

        while (urlEltsIterator.hasNext()) {
            Element urlElt = (Element) urlEltsIterator.next();

            String path = urlElt.getAttribute(ATT_PATH_PATTERN);

            if(!StringUtils.hasText(path)) {
                parserContext.getReaderContext().error("path attribute cannot be empty or null", urlElt);
            }

            if (useLowerCasePaths) {
                path = path.toLowerCase();
            }

            String method = urlElt.getAttribute(ATT_HTTP_METHOD);
            if (!StringUtils.hasText(method)) {
                method = null;
            }

            String access = urlElt.getAttribute(ATT_ACCESS_CONFIG);

            // Convert the comma-separated list of access attributes to a ConfigAttributeDefinition
            if (StringUtils.hasText(access)) {
                editor.setAsText(access);
                filterInvocationDefinitionMap.put(new RequestKey(path, method), editor.getValue());
            }
        }
        
        return filterInvocationDefinitionMap;
    }
    
}
