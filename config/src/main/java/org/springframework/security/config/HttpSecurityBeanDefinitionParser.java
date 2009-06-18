package org.springframework.security.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.PropertyValues;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.ConfigAttributeEditor;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.channel.InsecureChannelProcessor;
import org.springframework.security.web.access.channel.RetryWithHttpEntryPoint;
import org.springframework.security.web.access.channel.RetryWithHttpsEntryPoint;
import org.springframework.security.web.access.channel.SecureChannelProcessor;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.access.intercept.RequestKey;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.session.SessionFixationProtectionFilter;
import org.springframework.security.web.util.AntUrlPathMatcher;
import org.springframework.security.web.util.RegexUrlPathMatcher;
import org.springframework.security.web.util.UrlMatcher;
import org.springframework.security.web.wrapper.SecurityContextHolderAwareRequestFilter;
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
    private static final Log logger = LogFactory.getLog(HttpSecurityBeanDefinitionParser.class);

    static final String ATT_PATH_PATTERN = "pattern";
    static final String ATT_PATH_TYPE = "path-type";
    static final String OPT_PATH_TYPE_REGEX = "regex";
    private static final String DEF_PATH_TYPE_ANT = "ant";

    static final String ATT_FILTERS = "filters";
    static final String OPT_FILTERS_NONE = "none";

    private static final String ATT_REALM = "realm";
    private static final String DEF_REALM = "Spring Security Application";

    private static final String ATT_SESSION_FIXATION_PROTECTION = "session-fixation-protection";
    private static final String OPT_SESSION_FIXATION_NO_PROTECTION = "none";
    private static final String OPT_SESSION_FIXATION_MIGRATE_SESSION = "migrateSession";

    private static final String ATT_ACCESS_CONFIG = "access";
    static final String ATT_REQUIRES_CHANNEL = "requires-channel";
    private static final String OPT_REQUIRES_HTTP = "http";
    private static final String OPT_REQUIRES_HTTPS = "https";
    private static final String OPT_ANY_CHANNEL = "any";

    private static final String ATT_HTTP_METHOD = "method";

    private static final String ATT_CREATE_SESSION = "create-session";
    private static final String DEF_CREATE_SESSION_IF_REQUIRED = "ifRequired";
    private static final String OPT_CREATE_SESSION_ALWAYS = "always";
    private static final String OPT_CREATE_SESSION_NEVER = "never";

    private static final String ATT_LOWERCASE_COMPARISONS = "lowercase-comparisons";

    private static final String ATT_AUTO_CONFIG = "auto-config";

    private static final String ATT_SERVLET_API_PROVISION = "servlet-api-provision";
    private static final String DEF_SERVLET_API_PROVISION = "true";

    private static final String ATT_ACCESS_MGR = "access-decision-manager-ref";
    private static final String ATT_USER_SERVICE_REF = "user-service-ref";

    private static final String ATT_ENTRY_POINT_REF = "entry-point-ref";
    private static final String ATT_ONCE_PER_REQUEST = "once-per-request";
    private static final String ATT_ACCESS_DENIED_PAGE = "access-denied-page";
    private static final String ATT_ACCESS_DENIED_ERROR_PAGE = "error-page";

    private static final String ATT_USE_EXPRESSIONS = "use-expressions";

    private static final String ATT_SECURITY_CONTEXT_REPOSITORY = "security-context-repository-ref";

    private static final String ATT_DISABLE_URL_REWRITING = "disable-url-rewriting";

    static final String OPEN_ID_AUTHENTICATION_PROCESSING_FILTER_CLASS = "org.springframework.security.openid.OpenIDAuthenticationProcessingFilter";
    static final String OPEN_ID_AUTHENTICATION_PROVIDER_CLASS = "org.springframework.security.openid.OpenIDAuthenticationProvider";
    static final String AUTHENTICATION_PROCESSING_FILTER_CLASS = "org.springframework.security.web.authentication.UsernamePasswordAuthenticationProcessingFilter";

    static final String EXPRESSION_FIMDS_CLASS = "org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource";
    static final String EXPRESSION_HANDLER_CLASS = "org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler";
    private static final String EXPRESSION_HANDLER_ID = "_webExpressionHandler";

    @SuppressWarnings("unchecked")
    public BeanDefinition parse(Element element, ParserContext pc) {
        ConfigUtils.registerProviderManagerIfNecessary(pc);
        final BeanDefinitionRegistry registry = pc.getRegistry();
        final UrlMatcher matcher = createUrlMatcher(element);
        final Object source = pc.extractSource(element);
        // SEC-501 - should paths stored in request maps be converted to lower case
        // true if Ant path and using lower case
        final boolean convertPathsToLowerCase = (matcher instanceof AntUrlPathMatcher) && matcher.requiresLowerCaseUrl();
        final boolean allowSessionCreation = !OPT_CREATE_SESSION_NEVER.equals(element.getAttribute(ATT_CREATE_SESSION));

        final List<Element> interceptUrlElts = DomUtils.getChildElementsByTagName(element, Elements.INTERCEPT_URL);
        final Map filterChainMap =  new ManagedMap();
        final LinkedHashMap channelRequestMap = new LinkedHashMap();

        registerFilterChainProxy(pc, filterChainMap, matcher, source);

        // filterChainMap and channelRequestMap are populated by this call
        parseInterceptUrlsForChannelSecurityAndEmptyFilterChains(interceptUrlElts, filterChainMap, channelRequestMap,
                convertPathsToLowerCase, pc);

        // Add the default filter list
        List filterList = new ManagedList();
        filterChainMap.put(matcher.getUniversalMatchPattern(), filterList);

        BeanDefinition scpf = createSecurityContextPersistenceFilter(element, pc);
        pc.getRegistry().registerBeanDefinition(BeanIds.SECURITY_CONTEXT_PERSISTENCE_FILTER, scpf);
        ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.SECURITY_CONTEXT_PERSISTENCE_FILTER));

        BeanDefinition servApiFilter = createServletApiFilter(element, pc);
        if (servApiFilter != null) {
	        pc.getRegistry().registerBeanDefinition(BeanIds.SECURITY_CONTEXT_HOLDER_AWARE_REQUEST_FILTER,servApiFilter);
	        ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.SECURITY_CONTEXT_HOLDER_AWARE_REQUEST_FILTER));
        }
        // Register the portMapper. A default will always be created, even if no element exists.
        BeanDefinition portMapper = new PortMappingsBeanDefinitionParser().parse(
                DomUtils.getChildElementByTagName(element, Elements.PORT_MAPPINGS), pc);
        registry.registerBeanDefinition(BeanIds.PORT_MAPPER, portMapper);

        BeanDefinition etf = createExceptionTranslationFilter(element, pc, allowSessionCreation);
        pc.getRegistry().registerBeanDefinition(BeanIds.EXCEPTION_TRANSLATION_FILTER, etf);
        ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.EXCEPTION_TRANSLATION_FILTER));

        if (channelRequestMap.size() > 0) {
            // At least one channel requirement has been specified
            BeanDefinition cpf = createChannelProcessingFilter(pc, matcher, channelRequestMap);
            pc.getRegistry().registerBeanDefinition(BeanIds.CHANNEL_PROCESSING_FILTER, cpf);
            ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.CHANNEL_PROCESSING_FILTER));

        }

        boolean useExpressions = "true".equals(element.getAttribute(ATT_USE_EXPRESSIONS));

        LinkedHashMap<RequestKey, List<ConfigAttribute>> requestToAttributesMap =
            parseInterceptUrlsForFilterInvocationRequestMap(interceptUrlElts, convertPathsToLowerCase, useExpressions, pc);

        BeanDefinitionBuilder fidsBuilder;
        Class<? extends AccessDecisionVoter>[] voters;

        if (useExpressions) {
            Element expressionHandlerElt = DomUtils.getChildElementByTagName(element, Elements.EXPRESSION_HANDLER);
            String expressionHandlerRef = expressionHandlerElt == null ? null : expressionHandlerElt.getAttribute("ref");

            if (StringUtils.hasText(expressionHandlerRef)) {
                logger.info("Using bean '" + expressionHandlerRef + "' as web SecurityExpressionHandler implementation");
            } else {
                pc.getRegistry().registerBeanDefinition(EXPRESSION_HANDLER_ID,
                        BeanDefinitionBuilder.rootBeanDefinition(EXPRESSION_HANDLER_CLASS).getBeanDefinition());
                expressionHandlerRef = EXPRESSION_HANDLER_ID;
            }

            fidsBuilder = BeanDefinitionBuilder.rootBeanDefinition(EXPRESSION_FIMDS_CLASS);
            fidsBuilder.addConstructorArgValue(matcher);
            fidsBuilder.addConstructorArgValue(requestToAttributesMap);
            fidsBuilder.addConstructorArgReference(expressionHandlerRef);
            voters = new Class[] {WebExpressionVoter.class};
        } else {
            fidsBuilder = BeanDefinitionBuilder.rootBeanDefinition(DefaultFilterInvocationSecurityMetadataSource.class);
            fidsBuilder.addConstructorArgValue(matcher);
            fidsBuilder.addConstructorArgValue(requestToAttributesMap);
            voters = new Class[] {RoleVoter.class, AuthenticatedVoter.class};
        }
        fidsBuilder.addPropertyValue("stripQueryStringFromUrls", matcher instanceof AntUrlPathMatcher);

        // Set up the access manager reference for http
        String accessManagerId = element.getAttribute(ATT_ACCESS_MGR);

        if (!StringUtils.hasText(accessManagerId)) {
            pc.getRegistry().registerBeanDefinition(BeanIds.WEB_ACCESS_MANAGER,
                        ConfigUtils.createAccessManagerBean(voters));
            accessManagerId = BeanIds.WEB_ACCESS_MANAGER;
        }

        BeanDefinition fsi = createFilterSecurityInterceptor(element, pc, accessManagerId, fidsBuilder.getBeanDefinition());
        pc.getRegistry().registerBeanDefinition(BeanIds.FILTER_SECURITY_INTERCEPTOR, fsi);
        ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.FILTER_SECURITY_INTERCEPTOR));

        boolean sessionControlEnabled = false;

        BeanDefinition concurrentSessionFilter = createConcurrentSessionFilterAndRelatedBeansIfRequired(element, pc);
        if (concurrentSessionFilter != null) {
        	sessionControlEnabled = true;
	        pc.getRegistry().registerBeanDefinition(BeanIds.CONCURRENT_SESSION_FILTER, concurrentSessionFilter);
	        ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.CONCURRENT_SESSION_FILTER));
        }

        BeanDefinition sfpf = createSessionFixationProtectionFilter(pc, element.getAttribute(ATT_SESSION_FIXATION_PROTECTION),
                sessionControlEnabled);
        if (sfpf != null) {
        	pc.getRegistry().registerBeanDefinition(BeanIds.SESSION_FIXATION_PROTECTION_FILTER, sfpf);
        	ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.SESSION_FIXATION_PROTECTION_FILTER));
        }
        boolean autoConfig = "true".equals(element.getAttribute(ATT_AUTO_CONFIG));

        Element anonymousElt = DomUtils.getChildElementByTagName(element, Elements.ANONYMOUS);

        if (anonymousElt == null || !"false".equals(anonymousElt.getAttribute("enabled"))) {
        	BeanDefinition anonFilter = new AnonymousBeanDefinitionParser().parse(anonymousElt, pc);
            pc.getRegistry().registerBeanDefinition(BeanIds.ANONYMOUS_PROCESSING_FILTER, anonFilter);
            ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.ANONYMOUS_PROCESSING_FILTER));
        }

        parseRememberMeAndLogout(element, autoConfig, pc);

        String realm = element.getAttribute(ATT_REALM);
		if (!StringUtils.hasText(realm)) {
		    realm = DEF_REALM;
		}

		final FilterAndEntryPoint form = createFormLoginFilter(element, pc, autoConfig, allowSessionCreation);

		if (form.filter != null) {
		    pc.getRegistry().registerBeanDefinition(BeanIds.FORM_LOGIN_FILTER, form.filter);
		    ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.FORM_LOGIN_FILTER));
		    pc.getRegistry().registerBeanDefinition(BeanIds.FORM_LOGIN_ENTRY_POINT, form.entryPoint);
		}

		Element basicAuthElt = DomUtils.getChildElementByTagName(element, Elements.BASIC_AUTH);
		if (basicAuthElt != null || autoConfig) {
		    BeanDefinition basicFilter = new BasicAuthenticationBeanDefinitionParser(realm).parse(basicAuthElt, pc);
	        pc.getRegistry().registerBeanDefinition(BeanIds.BASIC_AUTHENTICATION_FILTER, basicFilter);
	        ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.BASIC_AUTHENTICATION_FILTER));
		}

		FilterAndEntryPoint openID = createOpenIDLoginFilter(element, pc, autoConfig, allowSessionCreation);

		if (openID.filter != null) {
		    pc.getRegistry().registerBeanDefinition(BeanIds.OPEN_ID_FILTER, openID.filter);
		    ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.OPEN_ID_FILTER));
		    pc.getRegistry().registerBeanDefinition(BeanIds.OPEN_ID_ENTRY_POINT, openID.entryPoint);
		}

		BeanDefinition loginPageGenerationFilter = createLoginPageFilterIfNeeded(form, openID);

		if (loginPageGenerationFilter != null) {
		    pc.getRegistry().registerBeanDefinition(BeanIds.DEFAULT_LOGIN_PAGE_GENERATING_FILTER, loginPageGenerationFilter);
		    ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.DEFAULT_LOGIN_PAGE_GENERATING_FILTER));
		}

        Element x509Elt = DomUtils.getChildElementByTagName(element, Elements.X509);
        if (x509Elt != null) {
            BeanDefinition x509Filter = new X509BeanDefinitionParser().parse(x509Elt, pc);
            pc.getRegistry().registerBeanDefinition(BeanIds.X509_FILTER, x509Filter);
            ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.X509_FILTER));
        }

		selectEntryPoint(element, pc, form, openID);

        // Register the post processors which will tie up the loose ends in the configuration once the app context has been created and all beans are available.
        RootBeanDefinition postProcessor = new RootBeanDefinition(EntryPointInjectionBeanPostProcessor.class);
        postProcessor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        registry.registerBeanDefinition(BeanIds.ENTRY_POINT_INJECTION_POST_PROCESSOR, postProcessor);
        RootBeanDefinition postProcessor2 = new RootBeanDefinition(UserDetailsServiceInjectionBeanPostProcessor.class);
        postProcessor2.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        registry.registerBeanDefinition(BeanIds.USER_DETAILS_SERVICE_INJECTION_POST_PROCESSOR, postProcessor2);

        return null;
    }

    private void parseRememberMeAndLogout(Element elt, boolean autoConfig, ParserContext pc) {
        // Parse remember me before logout as RememberMeServices is also a LogoutHandler implementation.
        Element rememberMeElt = DomUtils.getChildElementByTagName(elt, Elements.REMEMBER_ME);
        String rememberMeServices = null;

        if (rememberMeElt != null) {
            RememberMeBeanDefinitionParser rmbdp = new RememberMeBeanDefinitionParser();
            BeanDefinition filter = rmbdp.parse(rememberMeElt, pc);
            pc.getRegistry().registerBeanDefinition(BeanIds.REMEMBER_ME_FILTER, filter);
            ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.REMEMBER_ME_FILTER));
            rememberMeServices = rmbdp.getServicesName();
            // Post processor to inject RememberMeServices into filters which need it
            RootBeanDefinition rememberMeInjectionPostProcessor = new RootBeanDefinition(RememberMeServicesInjectionBeanPostProcessor.class);
            rememberMeInjectionPostProcessor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
            pc.getRegistry().registerBeanDefinition(BeanIds.REMEMBER_ME_SERVICES_INJECTION_POST_PROCESSOR, rememberMeInjectionPostProcessor);
        }

        Element logoutElt = DomUtils.getChildElementByTagName(elt, Elements.LOGOUT);
        if (logoutElt != null || autoConfig) {
            BeanDefinition logoutFilter = new LogoutBeanDefinitionParser(rememberMeServices).parse(logoutElt, pc);

            pc.getRegistry().registerBeanDefinition(BeanIds.LOGOUT_FILTER, logoutFilter);
            ConfigUtils.addHttpFilter(pc, new RuntimeBeanReference(BeanIds.LOGOUT_FILTER));
        }
    }

    @SuppressWarnings("unchecked")
    private void registerFilterChainProxy(ParserContext pc, Map filterChainMap, UrlMatcher matcher, Object source) {
        if (pc.getRegistry().containsBeanDefinition(BeanIds.FILTER_CHAIN_PROXY)) {
            pc.getReaderContext().error("Duplicate <http> element detected", source);
        }

        BeanDefinitionBuilder fcpBldr = BeanDefinitionBuilder.rootBeanDefinition(FilterChainProxy.class);
        fcpBldr.getRawBeanDefinition().setSource(source);
        fcpBldr.addPropertyValue("matcher", matcher);
        fcpBldr.addPropertyValue("stripQueryStringFromUrls", Boolean.valueOf(matcher instanceof AntUrlPathMatcher));
        fcpBldr.addPropertyValue("filterChainMap", filterChainMap);
        BeanDefinition fcpBean = fcpBldr.getBeanDefinition();
        pc.getRegistry().registerBeanDefinition(BeanIds.FILTER_CHAIN_PROXY, fcpBean);
        pc.getRegistry().registerAlias(BeanIds.FILTER_CHAIN_PROXY, BeanIds.SPRING_SECURITY_FILTER_CHAIN);
        pc.registerBeanComponent(new BeanComponentDefinition(fcpBean,BeanIds.FILTER_CHAIN_PROXY));
    }

    private BeanDefinition createSecurityContextPersistenceFilter(Element element, ParserContext pc) {
        BeanDefinitionBuilder scpf = BeanDefinitionBuilder.rootBeanDefinition(SecurityContextPersistenceFilter.class);

        String repoRef = element.getAttribute(ATT_SECURITY_CONTEXT_REPOSITORY);
        String createSession = element.getAttribute(ATT_CREATE_SESSION);
        String disableUrlRewriting = element.getAttribute(ATT_DISABLE_URL_REWRITING);

        if (StringUtils.hasText(repoRef)) {
            scpf.addPropertyReference("securityContextRepository", repoRef);

            if (OPT_CREATE_SESSION_ALWAYS.equals(createSession)) {
                scpf.addPropertyValue("forceEagerSessionCreation", Boolean.TRUE);
            } else if (StringUtils.hasText(createSession)) {
                pc.getReaderContext().error("If using security-context-repository-ref, the only value you can set for " +
                        "'create-session' is 'always'. Other session creation logic should be handled by the " +
                        "SecurityContextRepository", element);
            }
        } else {
            BeanDefinitionBuilder contextRepo = BeanDefinitionBuilder.rootBeanDefinition(HttpSessionSecurityContextRepository.class);
            if (OPT_CREATE_SESSION_ALWAYS.equals(createSession)) {
                contextRepo.addPropertyValue("allowSessionCreation", Boolean.TRUE);
                scpf.addPropertyValue("forceEagerSessionCreation", Boolean.TRUE);
            } else if (OPT_CREATE_SESSION_NEVER.equals(createSession)) {
                contextRepo.addPropertyValue("allowSessionCreation", Boolean.FALSE);
                scpf.addPropertyValue("forceEagerSessionCreation", Boolean.FALSE);
            } else {
                createSession = DEF_CREATE_SESSION_IF_REQUIRED;
                contextRepo.addPropertyValue("allowSessionCreation", Boolean.TRUE);
                scpf.addPropertyValue("forceEagerSessionCreation", Boolean.FALSE);
            }

            if ("true".equals(disableUrlRewriting)) {
                contextRepo.addPropertyValue("disableUrlRewriting", Boolean.TRUE);
            }

            scpf.addPropertyValue("securityContextRepository", contextRepo.getBeanDefinition());
        }

        return scpf.getBeanDefinition();
    }

    // Adds the servlet-api integration filter if required
    private RootBeanDefinition createServletApiFilter(Element element, ParserContext pc) {
        String provideServletApi = element.getAttribute(ATT_SERVLET_API_PROVISION);
        if (!StringUtils.hasText(provideServletApi)) {
            provideServletApi = DEF_SERVLET_API_PROVISION;
        }

        if ("true".equals(provideServletApi)) {
        	return new RootBeanDefinition(SecurityContextHolderAwareRequestFilter.class);
        }
        return null;
    }

    private BeanDefinition createConcurrentSessionFilterAndRelatedBeansIfRequired(Element element, ParserContext parserContext) {
        Element sessionControlElt = DomUtils.getChildElementByTagName(element, Elements.CONCURRENT_SESSIONS);
        if (sessionControlElt == null) {
            return null;
        }

        BeanDefinition sessionControlFilter = new ConcurrentSessionsBeanDefinitionParser().parse(sessionControlElt, parserContext);
        logger.info("Concurrent session filter in use, setting 'forceEagerSessionCreation' to true");
        BeanDefinition sessionIntegrationFilter = parserContext.getRegistry().getBeanDefinition(BeanIds.SECURITY_CONTEXT_PERSISTENCE_FILTER);
        sessionIntegrationFilter.getPropertyValues().addPropertyValue("forceEagerSessionCreation", Boolean.TRUE);
        return sessionControlFilter;
    }

    private BeanDefinition createExceptionTranslationFilter(Element element, ParserContext pc, boolean allowSessionCreation) {
        BeanDefinitionBuilder exceptionTranslationFilterBuilder
            = BeanDefinitionBuilder.rootBeanDefinition(ExceptionTranslationFilter.class);
        exceptionTranslationFilterBuilder.addPropertyValue("createSessionAllowed", Boolean.valueOf(allowSessionCreation));
        exceptionTranslationFilterBuilder.addPropertyValue("accessDeniedHandler", createAccessDeniedHandler(element, pc));


        return exceptionTranslationFilterBuilder.getBeanDefinition();
    }

    private BeanMetadataElement createAccessDeniedHandler(Element element, ParserContext pc) {
        String accessDeniedPage = element.getAttribute(ATT_ACCESS_DENIED_PAGE);
        ConfigUtils.validateHttpRedirect(accessDeniedPage, pc, pc.extractSource(element));
        Element accessDeniedElt = DomUtils.getChildElementByTagName(element, Elements.ACCESS_DENIED_HANDLER);
        BeanDefinitionBuilder accessDeniedHandler = BeanDefinitionBuilder.rootBeanDefinition(AccessDeniedHandlerImpl.class);

        if (StringUtils.hasText(accessDeniedPage)) {
            if (accessDeniedElt != null) {
                pc.getReaderContext().error("The attribute " + ATT_ACCESS_DENIED_PAGE +
                        " cannot be used with <" + Elements.ACCESS_DENIED_HANDLER + ">", pc.extractSource(accessDeniedElt));
            }

            accessDeniedHandler.addPropertyValue("errorPage", accessDeniedPage);
        }

        if (accessDeniedElt != null) {
            String errorPage = accessDeniedElt.getAttribute("error-page");
            String ref = accessDeniedElt.getAttribute("ref");

            if (StringUtils.hasText(errorPage)) {
                if (StringUtils.hasText(ref)) {
                    pc.getReaderContext().error("The attribute " + ATT_ACCESS_DENIED_ERROR_PAGE +
                            " cannot be used together with the 'ref' attribute within <" +
                            Elements.ACCESS_DENIED_HANDLER + ">", pc.extractSource(accessDeniedElt));

                }
                accessDeniedHandler.addPropertyValue("errorPage", errorPage);
            } else if (StringUtils.hasText(ref)) {
                return new RuntimeBeanReference(ref);
            }

        }

        return accessDeniedHandler.getBeanDefinition();
    }

    private BeanDefinition createFilterSecurityInterceptor(Element element, ParserContext pc, String accessManagerId,
            BeanDefinition fids) {
        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(FilterSecurityInterceptor.class);

        builder.addPropertyReference("accessDecisionManager", accessManagerId);
        builder.addPropertyReference("authenticationManager", BeanIds.AUTHENTICATION_MANAGER);

        if ("false".equals(element.getAttribute(ATT_ONCE_PER_REQUEST))) {
            builder.addPropertyValue("observeOncePerRequest", Boolean.FALSE);
        }

        builder.addPropertyValue("securityMetadataSource", fids);
        return builder.getBeanDefinition();
    }

    @SuppressWarnings("unchecked")
    private BeanDefinition createChannelProcessingFilter(ParserContext pc, UrlMatcher matcher, LinkedHashMap channelRequestMap) {
        RootBeanDefinition channelFilter = new RootBeanDefinition(ChannelProcessingFilter.class);
        channelFilter.getPropertyValues().addPropertyValue("channelDecisionManager",
                new RuntimeBeanReference(BeanIds.CHANNEL_DECISION_MANAGER));
        DefaultFilterInvocationSecurityMetadataSource channelFilterInvDefSource =
            new DefaultFilterInvocationSecurityMetadataSource(matcher, channelRequestMap);
        channelFilterInvDefSource.setStripQueryStringFromUrls(matcher instanceof AntUrlPathMatcher);

        channelFilter.getPropertyValues().addPropertyValue("securityMetadataSource", channelFilterInvDefSource);
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

        pc.getRegistry().registerBeanDefinition(BeanIds.CHANNEL_DECISION_MANAGER, channelDecisionManager);
        return channelFilter;
    }

    private BeanDefinition createSessionFixationProtectionFilter(ParserContext pc, String sessionFixationAttribute, boolean sessionControlEnabled) {
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
            return sessionFixationFilter.getBeanDefinition();
        }
        return null;
    }

    private FilterAndEntryPoint createFormLoginFilter(Element element, ParserContext pc, boolean autoConfig, boolean allowSessionCreation) {
        RootBeanDefinition formLoginFilter = null;
        RootBeanDefinition formLoginEntryPoint = null;

        Element formLoginElt = DomUtils.getChildElementByTagName(element, Elements.FORM_LOGIN);

        if (formLoginElt != null || autoConfig) {
            FormLoginBeanDefinitionParser parser = new FormLoginBeanDefinitionParser("/j_spring_security_check",
                    AUTHENTICATION_PROCESSING_FILTER_CLASS);

            parser.parse(formLoginElt, pc);
            formLoginFilter = parser.getFilterBean();
            formLoginEntryPoint = parser.getEntryPointBean();
        }

        if (formLoginFilter != null) {
            formLoginFilter.getPropertyValues().addPropertyValue("allowSessionCreation", new Boolean(allowSessionCreation));
        }

        return new FilterAndEntryPoint(formLoginFilter, formLoginEntryPoint);
    }

    private FilterAndEntryPoint createOpenIDLoginFilter(Element element, ParserContext pc, boolean autoConfig, boolean allowSessionCreation) {
        Element openIDLoginElt = DomUtils.getChildElementByTagName(element, Elements.OPENID_LOGIN);
        RootBeanDefinition openIDFilter = null;
        RootBeanDefinition openIDEntryPoint = null;

        if (openIDLoginElt != null) {
            FormLoginBeanDefinitionParser parser = new FormLoginBeanDefinitionParser("/j_spring_openid_security_check",
                    OPEN_ID_AUTHENTICATION_PROCESSING_FILTER_CLASS);

            parser.parse(openIDLoginElt, pc);
            openIDFilter = parser.getFilterBean();
            openIDEntryPoint = parser.getEntryPointBean();

            BeanDefinitionBuilder openIDProviderBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(OPEN_ID_AUTHENTICATION_PROVIDER_CLASS);

            String userService = openIDLoginElt.getAttribute(ATT_USER_SERVICE_REF);

            if (StringUtils.hasText(userService)) {
                openIDProviderBuilder.addPropertyReference("userDetailsService", userService);
            }

            BeanDefinition openIDProvider = openIDProviderBuilder.getBeanDefinition();
            pc.getRegistry().registerBeanDefinition(BeanIds.OPEN_ID_PROVIDER, openIDProvider);
            ConfigUtils.addAuthenticationProvider(pc, BeanIds.OPEN_ID_PROVIDER);
        }

        if (openIDFilter != null) {
            openIDFilter.getPropertyValues().addPropertyValue("allowSessionCreation", new Boolean(allowSessionCreation));
        }

        return new FilterAndEntryPoint(openIDFilter, openIDEntryPoint);
    }

    class FilterAndEntryPoint {
        RootBeanDefinition filter;
    	RootBeanDefinition entryPoint;

		public FilterAndEntryPoint(RootBeanDefinition filter, RootBeanDefinition entryPoint) {
			this.filter = filter;
			this.entryPoint = entryPoint;
		}
    }

    private void selectEntryPoint(Element element, ParserContext pc, FilterAndEntryPoint form, FilterAndEntryPoint openID) {
        // We need to establish the main entry point.
        // First check if a custom entry point bean is set
        String customEntryPoint = element.getAttribute(ATT_ENTRY_POINT_REF);

        if (StringUtils.hasText(customEntryPoint)) {
            pc.getRegistry().registerAlias(customEntryPoint, BeanIds.MAIN_ENTRY_POINT);
            return;
        }

        Element basicAuthElt = DomUtils.getChildElementByTagName(element, Elements.BASIC_AUTH);
        Element formLoginElt = DomUtils.getChildElementByTagName(element, Elements.FORM_LOGIN);
        Element openIDLoginElt = DomUtils.getChildElementByTagName(element, Elements.OPENID_LOGIN);
        // Basic takes precedence if explicit element is used and no others are configured
        if (basicAuthElt != null && formLoginElt == null && openIDLoginElt == null) {
            pc.getRegistry().registerAlias(BeanIds.BASIC_AUTHENTICATION_ENTRY_POINT, BeanIds.MAIN_ENTRY_POINT);
            return;
        }

        // If formLogin has been enabled either through an element or auto-config, then it is used if no openID login page
        // has been set
        String openIDLoginPage = getLoginFormUrl(openID.entryPoint);

        if (form.filter != null && openIDLoginPage == null) {
            pc.getRegistry().registerAlias(BeanIds.FORM_LOGIN_ENTRY_POINT, BeanIds.MAIN_ENTRY_POINT);
            return;
        }

        // Otherwise use OpenID if enabled
        if (openID.filter != null && form.filter == null) {
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
                "specify a custom AuthenticationEntryPoint with the '" + ATT_ENTRY_POINT_REF+ "' attribute ",
                pc.extractSource(element));
    }

    private String getLoginFormUrl(RootBeanDefinition entryPoint) {
    	if (entryPoint == null) {
    		return null;
    	}

    	PropertyValues pvs = entryPoint.getPropertyValues();
    	PropertyValue pv = pvs.getPropertyValue("loginFormUrl");
        if (pv == null) {
        	 return null;
        }

        return (String) pv.getValue();
    }


    BeanDefinition createLoginPageFilterIfNeeded(FilterAndEntryPoint form, FilterAndEntryPoint openID) {
        boolean needLoginPage = form.filter != null || openID.filter != null;
        String formLoginPage = getLoginFormUrl(form.entryPoint);
        // If the login URL is the default one, then it is assumed not to have been set explicitly
        if (DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL == formLoginPage) {
        	formLoginPage = null;
        }
        String openIDLoginPage = getLoginFormUrl(openID.entryPoint);

        // If no login page has been defined, add in the default page generator.
        if (needLoginPage && formLoginPage == null && openIDLoginPage == null) {
            logger.info("No login page configured. The default internal one will be used. Use the '"
                     + FormLoginBeanDefinitionParser.ATT_LOGIN_PAGE + "' attribute to set the URL of the login page.");
            BeanDefinitionBuilder loginPageFilter =
                BeanDefinitionBuilder.rootBeanDefinition(DefaultLoginPageGeneratingFilter.class);

            if (form.filter != null) {
                loginPageFilter.addConstructorArgValue(new RuntimeBeanReference(BeanIds.FORM_LOGIN_FILTER));
            }

            if (openID.filter != null) {
                loginPageFilter.addConstructorArgValue(new RuntimeBeanReference(BeanIds.OPEN_ID_FILTER));
            }

            return loginPageFilter.getBeanDefinition();
        }
        return null;
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
    @SuppressWarnings("unchecked")
    void parseInterceptUrlsForChannelSecurityAndEmptyFilterChains(List<Element> urlElts, Map filterChainMap,  Map channelRequestMap,
            boolean useLowerCasePaths, ParserContext parserContext) {

        ConfigAttributeEditor editor = new ConfigAttributeEditor();

        for (Element urlElt : urlElts) {
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
                channelRequestMap.put(new RequestKey(path), editor.getValue());
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

    /**
     * Parses the filter invocation map which will be used to configure the FilterInvocationSecurityMetadataSource
     * used in the security interceptor.
     */
    static LinkedHashMap<RequestKey, List<ConfigAttribute>>
    parseInterceptUrlsForFilterInvocationRequestMap(List<Element> urlElts,  boolean useLowerCasePaths,
            boolean useExpressions, ParserContext parserContext) {

        LinkedHashMap<RequestKey, List<ConfigAttribute>> filterInvocationDefinitionMap = new LinkedHashMap<RequestKey, List<ConfigAttribute>>();

        for (Element urlElt : urlElts) {
            String access = urlElt.getAttribute(ATT_ACCESS_CONFIG);
            if (!StringUtils.hasText(access)) {
                continue;
            }

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

            // Convert the comma-separated list of access attributes to a List<ConfigAttribute>

            RequestKey key = new RequestKey(path, method);
            List<ConfigAttribute> attributes = null;

            if (useExpressions) {
                logger.info("Creating access control expression attribute '" + access + "' for " + key);
                attributes = new ArrayList<ConfigAttribute>(1);
                // The expression will be parsed later by the ExpressionFilterInvocationSecurityMetadataSource
                attributes.add(new SecurityConfig(access));

            } else {
                attributes = SecurityConfig.createList(StringUtils.commaDelimitedListToStringArray(access));
            }

            if (filterInvocationDefinitionMap.containsKey(key)) {
                logger.warn("Duplicate URL defined: " + key + ". The original attribute values will be overwritten");
            }

            filterInvocationDefinitionMap.put(key, attributes);
        }

        return filterInvocationDefinitionMap;
    }

}
