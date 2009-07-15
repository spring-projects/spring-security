package org.springframework.security.config;

import static org.springframework.security.config.FilterChainOrder.*;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.authentication.concurrent.ConcurrentSessionControllerImpl;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
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
import org.springframework.security.web.authentication.AnonymousProcessingFilter;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor;
import org.springframework.security.web.authentication.preauth.x509.X509PreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicProcessingFilter;
import org.springframework.security.web.authentication.www.BasicProcessingFilterEntryPoint;
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

    final SecureRandom random;

    public HttpSecurityBeanDefinitionParser() {
         try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            // Shouldn't happen...
            throw new RuntimeException("Failed find SHA1PRNG algorithm!");
        }
    }

    /**
     * The aim of this method is to build the list of filters which have been defined by the namespace elements
     * and attributes within the &lt;http&gt; configuration, along with any custom-filter's linked to user-defined
     * filter beans.
     * <p>
     * By the end of this method, the default <tt>FilterChainProxy</tt> bean should have been registered and will have
     * the map of filter chains defined, with the "universal" match pattern mapped to the list of beans which have been parsed here.
     */
    public BeanDefinition parse(Element element, ParserContext pc) {
//        ConfigUtils.registerProviderManagerIfNecessary(pc, element);
        CompositeComponentDefinition compositeDef =
            new CompositeComponentDefinition(element.getTagName(), pc.extractSource(element));
        pc.pushContainingComponent(compositeDef);

        final UrlMatcher matcher = createUrlMatcher(element);
        final Object source = pc.extractSource(element);
        // SEC-501 - should paths stored in request maps be converted to lower case
        // true if Ant path and using lower case
        final boolean convertPathsToLowerCase = (matcher instanceof AntUrlPathMatcher) && matcher.requiresLowerCaseUrl();
        final boolean allowSessionCreation = !OPT_CREATE_SESSION_NEVER.equals(element.getAttribute(ATT_CREATE_SESSION));
        final boolean autoConfig = "true".equals(element.getAttribute(ATT_AUTO_CONFIG));
        final Map<String, List<BeanMetadataElement>> filterChainMap =  new ManagedMap<String, List<BeanMetadataElement>>();
        final LinkedHashMap<RequestKey, List<ConfigAttribute>> channelRequestMap = new LinkedHashMap<RequestKey, List<ConfigAttribute>>();

        // filterChainMap and channelRequestMap are populated by this call
        parseInterceptUrlsForChannelSecurityAndEmptyFilterChains(DomUtils.getChildElementsByTagName(element, Elements.INTERCEPT_URL),
                filterChainMap, channelRequestMap, convertPathsToLowerCase, pc);

        BeanDefinition cpf = null;
        BeanReference sessionRegistryRef = null;
        BeanReference concurrentSessionControllerRef = null;
        BeanDefinition concurrentSessionFilter = createConcurrentSessionFilterAndRelatedBeansIfRequired(element, pc);

        BeanDefinition scpf = createSecurityContextPersistenceFilter(element, pc);

        if (concurrentSessionFilter != null) {
            sessionRegistryRef = (BeanReference)
                    concurrentSessionFilter.getPropertyValues().getPropertyValue("sessionRegistry").getValue();
            logger.info("Concurrent session filter in use, setting 'forceEagerSessionCreation' to true");
            scpf.getPropertyValues().addPropertyValue("forceEagerSessionCreation", Boolean.TRUE);
            concurrentSessionControllerRef = createConcurrentSessionController(element, concurrentSessionFilter, sessionRegistryRef, pc);
        }

        ManagedList<BeanReference> authenticationProviders = new ManagedList<BeanReference>();
        BeanReference authenticationManager = createAuthenticationManager(element, pc, authenticationProviders, concurrentSessionControllerRef);

        BeanDefinition servApiFilter = createServletApiFilter(element, pc);
        // Register the portMapper. A default will always be created, even if no element exists.
        BeanDefinition portMapper = new PortMappingsBeanDefinitionParser().parse(
                DomUtils.getChildElementByTagName(element, Elements.PORT_MAPPINGS), pc);
        RootBeanDefinition rememberMeFilter = createRememberMeFilter(element, pc, authenticationManager);
        BeanDefinition anonFilter = createAnonymousFilter(element, pc);

        BeanDefinition etf = createExceptionTranslationFilter(element, pc, allowSessionCreation);
        RootBeanDefinition sfpf = createSessionFixationProtectionFilter(pc, element.getAttribute(ATT_SESSION_FIXATION_PROTECTION),
                sessionRegistryRef);
        BeanDefinition fsi = createFilterSecurityInterceptor(element, pc, matcher, convertPathsToLowerCase, authenticationManager);

        String portMapperName = pc.getReaderContext().registerWithGeneratedName(portMapper);
        if (channelRequestMap.size() > 0) {
            // At least one channel requirement has been specified
            cpf = createChannelProcessingFilter(pc, matcher, channelRequestMap, portMapperName);
        }

        if (sfpf != null) {
            // Used by SessionRegistrynjectionPP
            pc.getRegistry().registerBeanDefinition(BeanIds.SESSION_FIXATION_PROTECTION_FILTER, sfpf);
        }

        final FilterAndEntryPoint basic = createBasicFilter(element, pc, autoConfig, authenticationManager);
        final FilterAndEntryPoint form = createFormLoginFilter(element, pc, autoConfig, allowSessionCreation,
                sfpf, authenticationManager);
        final FilterAndEntryPoint openID = createOpenIDLoginFilter(element, pc, autoConfig, allowSessionCreation,
                sfpf, authenticationManager);

        String rememberMeServicesId = null;
        if (rememberMeFilter != null) {
            rememberMeServicesId = ((RuntimeBeanReference) rememberMeFilter.getPropertyValues().getPropertyValue("rememberMeServices").getValue()).getBeanName();
        }

        final BeanDefinition logoutFilter = createLogoutFilter(element, autoConfig, pc, rememberMeServicesId);

        BeanDefinition loginPageGenerationFilter = createLoginPageFilterIfNeeded(form, openID);

        if (form.filter != null) {
            // Required by login page filter
            pc.getRegistry().registerBeanDefinition(BeanIds.FORM_LOGIN_FILTER, form.filter);
            pc.registerBeanComponent(new BeanComponentDefinition(form.filter, BeanIds.FORM_LOGIN_FILTER));
            injectRememberMeServicesRef(form.filter, rememberMeServicesId);
            injectSessionRegistryRef(form.filter, sessionRegistryRef);
        }

        if (openID.filter != null) {
            // Required by login page filter
            pc.getRegistry().registerBeanDefinition(BeanIds.OPEN_ID_FILTER, openID.filter);
            pc.registerBeanComponent(new BeanComponentDefinition(openID.filter, BeanIds.OPEN_ID_FILTER));
            injectRememberMeServicesRef(openID.filter, rememberMeServicesId);
            injectSessionRegistryRef(openID.filter, sessionRegistryRef);
        }

        String x509ProviderId = null;
        FilterAndEntryPoint x509 = createX509Filter(element, pc, authenticationManager);

        BeanMetadataElement entryPoint = selectEntryPoint(element, pc, basic, form, openID, x509);
        etf.getPropertyValues().addPropertyValue("authenticationEntryPoint", entryPoint);

        List<OrderDecorator> unorderedFilterChain = new ArrayList<OrderDecorator>();

        if (cpf != null) {
            unorderedFilterChain.add(new OrderDecorator(cpf, CHANNEL_FILTER));
        }

        if (concurrentSessionFilter != null) {
            unorderedFilterChain.add(new OrderDecorator(concurrentSessionFilter, CONCURRENT_SESSION_FILTER));
        }

        unorderedFilterChain.add(new OrderDecorator(scpf, SECURITY_CONTEXT_FILTER));

        if (logoutFilter != null) {
            unorderedFilterChain.add(new OrderDecorator(logoutFilter, LOGOUT_FILTER));
        }

        if (x509.filter != null) {
            unorderedFilterChain.add(new OrderDecorator(x509.filter, X509_FILTER));
            BeanReference x509Provider = createX509Provider(element, pc);
            x509ProviderId = x509Provider.getBeanName();
            authenticationProviders.add(x509Provider);
        }

        if (form.filter != null) {
            unorderedFilterChain.add(new OrderDecorator(form.filter, AUTHENTICATION_PROCESSING_FILTER));
        }

        if (openID.filter != null) {
            unorderedFilterChain.add(new OrderDecorator(openID.filter, OPENID_PROCESSING_FILTER));
            authenticationProviders.add(createOpenIDProvider(element, pc));
        }

        if (loginPageGenerationFilter != null) {
            unorderedFilterChain.add(new OrderDecorator(loginPageGenerationFilter, LOGIN_PAGE_FILTER));
        }

        if (basic.filter != null) {
            unorderedFilterChain.add(new OrderDecorator(basic.filter, BASIC_PROCESSING_FILTER));
        }

        if (servApiFilter != null) {
            unorderedFilterChain.add(new OrderDecorator(servApiFilter, SERVLET_API_SUPPORT_FILTER));
        }

        if (rememberMeFilter != null) {
            unorderedFilterChain.add(new OrderDecorator(rememberMeFilter, REMEMBER_ME_FILTER));
            authenticationProviders.add(createRememberMeProvider(rememberMeFilter, pc, rememberMeServicesId));
        }

        if (anonFilter != null) {
            unorderedFilterChain.add(new OrderDecorator(anonFilter, ANONYMOUS_FILTER));
            authenticationProviders.add(createAnonymousProvider(anonFilter, pc));
        }

        unorderedFilterChain.add(new OrderDecorator(etf, EXCEPTION_TRANSLATION_FILTER));

        if (sfpf != null) {
            unorderedFilterChain.add(new OrderDecorator(sfpf, SESSION_FIXATION_FILTER));
        }

        unorderedFilterChain.add(new OrderDecorator(fsi, FILTER_SECURITY_INTERCEPTOR));


        List<OrderDecorator> customFilters = buildCustomFilterList(element, pc);

        unorderedFilterChain.addAll(customFilters);

        Collections.sort(unorderedFilterChain, new OrderComparator());
        checkFilterChainOrder(unorderedFilterChain, pc, source);

        List<BeanMetadataElement> filterChain = new ManagedList<BeanMetadataElement>();

        for (OrderDecorator od : unorderedFilterChain) {
            filterChain.add(od.bean);
        }

        filterChainMap.put(matcher.getUniversalMatchPattern(), filterChain);

        registerFilterChainProxy(pc, filterChainMap, matcher, source);

        BeanDefinitionBuilder userServiceInjector = BeanDefinitionBuilder.rootBeanDefinition(UserDetailsServiceInjectionBeanPostProcessor.class);
        userServiceInjector.addConstructorArgValue(x509ProviderId);
        userServiceInjector.addConstructorArgValue(rememberMeServicesId);
        userServiceInjector.addConstructorArgValue(rememberMeServicesId);
        userServiceInjector.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        pc.getReaderContext().registerWithGeneratedName(userServiceInjector.getBeanDefinition());

        pc.popAndRegisterContainingComponent();
        return null;
    }

    /**
     * Creates the internal AuthentiationManager bean which uses the externally registered (global) one as
     * a parent.
     *
     * All the providers registered by this &lt;http&gt; block will be registered with the internal
     * authentication manager, along with the ConcurrentSessionController (if necessary).
     */
    private BeanReference createAuthenticationManager(Element element, ParserContext pc,
            ManagedList<BeanReference> authenticationProviders, BeanReference concurrencyController) {
        BeanDefinitionBuilder authManager = BeanDefinitionBuilder.rootBeanDefinition(ProviderManager.class);
        authManager.addPropertyReference("parent", BeanIds.AUTHENTICATION_MANAGER);
        authManager.addPropertyValue("providers", authenticationProviders);

        if (concurrencyController != null) {
            authManager.addPropertyValue("sessionController", concurrencyController);
        }
        authManager.getRawBeanDefinition().setSource(pc.extractSource(element));
        String id = pc.getReaderContext().registerWithGeneratedName(authManager.getBeanDefinition());

        return new RuntimeBeanReference(id);
    }

    private void injectRememberMeServicesRef(RootBeanDefinition bean, String rememberMeServicesId) {
        if (rememberMeServicesId != null) {
            bean.getPropertyValues().addPropertyValue("rememberMeServices", new RuntimeBeanReference(rememberMeServicesId));
        }
    }

    private void injectSessionRegistryRef(RootBeanDefinition bean, BeanReference sessionRegistryRef){
        if (sessionRegistryRef != null) {
            bean.getPropertyValues().addPropertyValue("sessionRegistry", sessionRegistryRef);
        }
    }

    private void checkFilterChainOrder(List<OrderDecorator> filters, ParserContext pc, Object source) {
        logger.info("Checking sorted filter chain: " + filters);

        for(int i=0; i < filters.size(); i++) {
            OrderDecorator filter = (OrderDecorator)filters.get(i);

            if (i > 0) {
                OrderDecorator previous = (OrderDecorator)filters.get(i-1);
                if (filter.getOrder() == previous.getOrder()) {
                    pc.getReaderContext().error("Filter beans '" + filter.bean + "' and '" +
                            previous.bean + "' have the same 'order' value. When using custom filters, " +
                                    "please make sure the positions do not conflict with default filters. " +
                                    "Alternatively you can disable the default filters by removing the corresponding " +
                                    "child elements from <http> and avoiding the use of <http auto-config='true'>.", source);
                }
            }
        }
    }

    private class OrderDecorator implements Ordered {
        BeanMetadataElement bean;
        int order;

        public OrderDecorator(BeanMetadataElement bean, int order) {
            super();
            this.bean = bean;
            this.order = order;
        }

        public int getOrder() {
            return order;
        }

        public String toString() {
            return bean + ", order = " + order;
        }
    }

    List<OrderDecorator> buildCustomFilterList(Element element, ParserContext pc) {
        List<Element> customFilterElts = DomUtils.getChildElementsByTagName(element, Elements.CUSTOM_FILTER);
        List<OrderDecorator> customFilters = new ArrayList<OrderDecorator>();

        final String ATT_AFTER = "after";
        final String ATT_BEFORE = "before";
        final String ATT_POSITION = "position";
        final String REF = "ref";

        for (Element elt: customFilterElts) {
            String after = elt.getAttribute(ATT_AFTER);
            String before = elt.getAttribute(ATT_BEFORE);
            String position = elt.getAttribute(ATT_POSITION);

            String ref = elt.getAttribute(REF);

            if (!StringUtils.hasText(ref)) {
                pc.getReaderContext().error("The '" + REF + "' attribute must be supplied", pc.extractSource(elt));
            }

            RuntimeBeanReference bean = new RuntimeBeanReference(ref);

            if(ConfigUtils.countNonEmpty(new String[] {after, before, position}) != 1) {
                pc.getReaderContext().error("A single '" + ATT_AFTER + "', '" + ATT_BEFORE + "', or '" +
                        ATT_POSITION + "' attribute must be supplied", pc.extractSource(elt));
            }

            if (StringUtils.hasText(position)) {
                customFilters.add(new OrderDecorator(bean, FilterChainOrder.getOrder(position)));
            } else if (StringUtils.hasText(after)) {
                int order = FilterChainOrder.getOrder(after);
                customFilters.add(new OrderDecorator(bean, order == Integer.MAX_VALUE ? order : order + 1));
            } else if (StringUtils.hasText(before)) {
                int order = FilterChainOrder.getOrder(before);
                customFilters.add(new OrderDecorator(bean, order == Integer.MIN_VALUE ? order : order - 1));
            }
        }

        return customFilters;
    }

    private BeanDefinition createAnonymousFilter(Element element, ParserContext pc) {
        Element anonymousElt = DomUtils.getChildElementByTagName(element, Elements.ANONYMOUS);

        if (anonymousElt != null && "false".equals(anonymousElt.getAttribute("enabled"))) {
            return null;
        }

        String grantedAuthority = null;
        String username = null;
        String key = null;
        Object source = pc.extractSource(element);

        if (anonymousElt != null) {
            grantedAuthority = element.getAttribute("granted-authority");
            username = element.getAttribute("username");
            key = element.getAttribute("key");
            source = pc.extractSource(anonymousElt);
        }

        if (!StringUtils.hasText(grantedAuthority)) {
            grantedAuthority = "ROLE_ANONYMOUS";
        }

        if (!StringUtils.hasText(username)) {
            username = "anonymousUser";
        }

        if (!StringUtils.hasText(key)) {
            // Generate a random key for the Anonymous provider
            key = Long.toString(random.nextLong());
        }

        RootBeanDefinition filter = new RootBeanDefinition(AnonymousProcessingFilter.class);

        PropertyValue keyPV = new PropertyValue("key", key);
        filter.setSource(source);
        filter.getPropertyValues().addPropertyValue("userAttribute", username + "," + grantedAuthority);
        filter.getPropertyValues().addPropertyValue(keyPV);

        return filter;
    }

    private BeanReference createAnonymousProvider(BeanDefinition anonFilter, ParserContext pc) {
        RootBeanDefinition provider = new RootBeanDefinition(AnonymousAuthenticationProvider.class);
        provider.setSource(anonFilter.getSource());
        provider.getPropertyValues().addPropertyValue(anonFilter.getPropertyValues().getPropertyValue("key"));
        String id = pc.getReaderContext().registerWithGeneratedName(provider);
        pc.registerBeanComponent(new BeanComponentDefinition(provider, id));

        return new RuntimeBeanReference(id);
    }

    private FilterAndEntryPoint createBasicFilter(Element elt, ParserContext pc,
            boolean autoConfig, BeanReference authManager) {
        Element basicAuthElt = DomUtils.getChildElementByTagName(elt, Elements.BASIC_AUTH);

        String realm = elt.getAttribute(ATT_REALM);
        if (!StringUtils.hasText(realm)) {
            realm = DEF_REALM;
        }

        RootBeanDefinition filter = null;
        RootBeanDefinition entryPoint = null;

        if (basicAuthElt != null || autoConfig) {
            BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder.rootBeanDefinition(BasicProcessingFilter.class);
            entryPoint = new RootBeanDefinition(BasicProcessingFilterEntryPoint.class);
            entryPoint.setSource(pc.extractSource(elt));

            entryPoint.getPropertyValues().addPropertyValue("realmName", realm);

            String entryPointId = pc.getReaderContext().registerWithGeneratedName(entryPoint);

            filterBuilder.addPropertyValue("authenticationManager", authManager);
            filterBuilder.addPropertyValue("authenticationEntryPoint", new RuntimeBeanReference(entryPointId));
            filter = (RootBeanDefinition) filterBuilder.getBeanDefinition();
        }

        return new FilterAndEntryPoint(filter, entryPoint);
    }

    private FilterAndEntryPoint createX509Filter(Element elt, ParserContext pc, BeanReference authManager) {
        Element x509Elt = DomUtils.getChildElementByTagName(elt, Elements.X509);
        RootBeanDefinition filter = null;
        RootBeanDefinition entryPoint = null;

        if (x509Elt != null) {
            BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder.rootBeanDefinition(X509PreAuthenticatedProcessingFilter.class);
            filterBuilder.getRawBeanDefinition().setSource(pc.extractSource(x509Elt));
            filterBuilder.addPropertyValue("authenticationManager", authManager);

            String regex = x509Elt.getAttribute("subject-principal-regex");

            if (StringUtils.hasText(regex)) {
                SubjectDnX509PrincipalExtractor extractor = new SubjectDnX509PrincipalExtractor();
                extractor.setSubjectDnRegex(regex);

                filterBuilder.addPropertyValue("principalExtractor", extractor);
            }
            filter = (RootBeanDefinition) filterBuilder.getBeanDefinition();
            entryPoint = new RootBeanDefinition(Http403ForbiddenEntryPoint.class);
            entryPoint.setSource(pc.extractSource(x509Elt));
        }

        return new FilterAndEntryPoint(filter, entryPoint);
    }

    private BeanReference createX509Provider(Element elt, ParserContext pc) {
        Element x509Elt = DomUtils.getChildElementByTagName(elt, Elements.X509);
        BeanDefinition provider = new RootBeanDefinition(PreAuthenticatedAuthenticationProvider.class);

        String userServiceRef = x509Elt.getAttribute(ATT_USER_SERVICE_REF);

        if (StringUtils.hasText(userServiceRef)) {
            RootBeanDefinition preAuthUserService = new RootBeanDefinition(UserDetailsByNameServiceWrapper.class);
            preAuthUserService.setSource(pc.extractSource(x509Elt));
            preAuthUserService.getPropertyValues().addPropertyValue("userDetailsService", new RuntimeBeanReference(userServiceRef));
            provider.getPropertyValues().addPropertyValue("preAuthenticatedUserDetailsService", preAuthUserService);
        }

        String id = pc.getReaderContext().registerWithGeneratedName(provider);
        return new RuntimeBeanReference(id);
    }

    private BeanDefinition createLogoutFilter(Element elt, boolean autoConfig, ParserContext pc, String rememberMeServicesId) {
        Element logoutElt = DomUtils.getChildElementByTagName(elt, Elements.LOGOUT);
        if (logoutElt != null || autoConfig) {
            BeanDefinition logoutFilter = new LogoutBeanDefinitionParser(rememberMeServicesId).parse(logoutElt, pc);

            return logoutFilter;
        }
        return null;
    }

    private RootBeanDefinition createRememberMeFilter(Element elt, ParserContext pc, BeanReference authenticationManager) {
        // Parse remember me before logout as RememberMeServices is also a LogoutHandler implementation.
        Element rememberMeElt = DomUtils.getChildElementByTagName(elt, Elements.REMEMBER_ME);

        if (rememberMeElt != null) {
            RootBeanDefinition filter = (RootBeanDefinition) new RememberMeBeanDefinitionParser().parse(rememberMeElt, pc);
            filter.getPropertyValues().addPropertyValue("authenticationManager", authenticationManager);
            return filter;
        }

        return null;
    }

    private BeanReference createRememberMeProvider(BeanDefinition filter, ParserContext pc, String servicesId) {
        RootBeanDefinition provider = new RootBeanDefinition(RememberMeAuthenticationProvider.class);
        provider.setSource(filter.getSource());
        // Locate the RememberMeServices bean and read the "key" property from it
        PropertyValue key = null;
        if (pc.getRegistry().containsBeanDefinition(servicesId)) {
            BeanDefinition services = pc.getRegistry().getBeanDefinition(servicesId);

            key = services.getPropertyValues().getPropertyValue("key");
        }

        if (key == null) {
            key = new PropertyValue("key", RememberMeBeanDefinitionParser.DEF_KEY);
        }

        provider.getPropertyValues().addPropertyValue(key);

        String id = pc.getReaderContext().registerWithGeneratedName(provider);
        pc.registerBeanComponent(new BeanComponentDefinition(provider, id));

        return new RuntimeBeanReference(id);
    }

    private void registerFilterChainProxy(ParserContext pc, Map<String, List<BeanMetadataElement>> filterChainMap, UrlMatcher matcher, Object source) {
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
        pc.registerBeanComponent(new BeanComponentDefinition(fcpBean, BeanIds.FILTER_CHAIN_PROXY));
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
        return sessionControlFilter;
    }

    private BeanReference createConcurrentSessionController(Element elt, BeanDefinition filter, BeanReference sessionRegistry, ParserContext pc) {
        BeanDefinitionBuilder controllerBuilder = BeanDefinitionBuilder.rootBeanDefinition(ConcurrentSessionControllerImpl.class);
        Element sessionCtrlElement = DomUtils.getChildElementByTagName(elt, Elements.CONCURRENT_SESSIONS);
        controllerBuilder.getRawBeanDefinition().setSource(filter.getSource());
        controllerBuilder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        controllerBuilder.addPropertyValue("sessionRegistry", sessionRegistry);

        String maxSessions = sessionCtrlElement.getAttribute("max-sessions");

        if (StringUtils.hasText(maxSessions)) {
            controllerBuilder.addPropertyValue("maximumSessions", maxSessions);
        }

        String exceptionIfMaximumExceeded = sessionCtrlElement.getAttribute("exception-if-maximum-exceeded");

        if (StringUtils.hasText(exceptionIfMaximumExceeded)) {
            controllerBuilder.addPropertyValue("exceptionIfMaximumExceeded", exceptionIfMaximumExceeded);
        }

        BeanDefinition controller = controllerBuilder.getBeanDefinition();

        String id = pc.getReaderContext().registerWithGeneratedName(controller);
        pc.registerComponent(new BeanComponentDefinition(controller, id));
        return new RuntimeBeanReference(id);
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

    @SuppressWarnings("unchecked")
    private BeanDefinition createFilterSecurityInterceptor(Element element, ParserContext pc, UrlMatcher matcher,
            boolean convertPathsToLowerCase, BeanReference authManager) {
        BeanDefinitionBuilder fidsBuilder;

        boolean useExpressions = "true".equals(element.getAttribute(ATT_USE_EXPRESSIONS));

        LinkedHashMap<RequestKey, List<ConfigAttribute>> requestToAttributesMap =
            parseInterceptUrlsForFilterInvocationRequestMap(DomUtils.getChildElementsByTagName(element, Elements.INTERCEPT_URL),
                    convertPathsToLowerCase, useExpressions, pc);


        RootBeanDefinition accessDecisionMgr;

        if (useExpressions) {
            Element expressionHandlerElt = DomUtils.getChildElementByTagName(element, Elements.EXPRESSION_HANDLER);
            String expressionHandlerRef = expressionHandlerElt == null ? null : expressionHandlerElt.getAttribute("ref");

            if (StringUtils.hasText(expressionHandlerRef)) {
                logger.info("Using bean '" + expressionHandlerRef + "' as web SecurityExpressionHandler implementation");
            } else {
                BeanDefinition expressionHandler = BeanDefinitionBuilder.rootBeanDefinition(EXPRESSION_HANDLER_CLASS).getBeanDefinition();
                expressionHandlerRef = pc.getReaderContext().registerWithGeneratedName(expressionHandler);
                pc.registerBeanComponent(new BeanComponentDefinition(expressionHandler, expressionHandlerRef));
            }

            fidsBuilder = BeanDefinitionBuilder.rootBeanDefinition(EXPRESSION_FIMDS_CLASS);
            fidsBuilder.addConstructorArgValue(matcher);
            fidsBuilder.addConstructorArgValue(requestToAttributesMap);
            fidsBuilder.addConstructorArgReference(expressionHandlerRef);
            accessDecisionMgr = ConfigUtils.createAccessManagerBean(WebExpressionVoter.class);
        } else {
            fidsBuilder = BeanDefinitionBuilder.rootBeanDefinition(DefaultFilterInvocationSecurityMetadataSource.class);
            fidsBuilder.addConstructorArgValue(matcher);
            fidsBuilder.addConstructorArgValue(requestToAttributesMap);
            accessDecisionMgr = ConfigUtils.createAccessManagerBean(RoleVoter.class, AuthenticatedVoter.class);
        }
        accessDecisionMgr.setSource(pc.extractSource(element));
        fidsBuilder.addPropertyValue("stripQueryStringFromUrls", matcher instanceof AntUrlPathMatcher);

        // Set up the access manager reference for http
        String accessManagerId = element.getAttribute(ATT_ACCESS_MGR);

        if (!StringUtils.hasText(accessManagerId)) {
            pc.getRegistry().registerBeanDefinition(BeanIds.WEB_ACCESS_MANAGER, accessDecisionMgr);
            pc.registerBeanComponent(new BeanComponentDefinition(accessDecisionMgr, BeanIds.WEB_ACCESS_MANAGER));
            accessManagerId = BeanIds.WEB_ACCESS_MANAGER;
        }

        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(FilterSecurityInterceptor.class);

        builder.addPropertyReference("accessDecisionManager", accessManagerId);
        builder.addPropertyValue("authenticationManager", authManager);

        if ("false".equals(element.getAttribute(ATT_ONCE_PER_REQUEST))) {
            builder.addPropertyValue("observeOncePerRequest", Boolean.FALSE);
        }

        builder.addPropertyValue("securityMetadataSource", fidsBuilder.getBeanDefinition());
        return builder.getBeanDefinition();
    }

    private BeanDefinition createChannelProcessingFilter(ParserContext pc, UrlMatcher matcher,
            LinkedHashMap<RequestKey, List<ConfigAttribute>> channelRequestMap, String portMapperBeanName) {
        RootBeanDefinition channelFilter = new RootBeanDefinition(ChannelProcessingFilter.class);

        DefaultFilterInvocationSecurityMetadataSource channelFilterInvDefSource =
            new DefaultFilterInvocationSecurityMetadataSource(matcher, channelRequestMap);
        channelFilterInvDefSource.setStripQueryStringFromUrls(matcher instanceof AntUrlPathMatcher);

        channelFilter.getPropertyValues().addPropertyValue("securityMetadataSource", channelFilterInvDefSource);
        RootBeanDefinition channelDecisionManager = new RootBeanDefinition(ChannelDecisionManagerImpl.class);
        ManagedList<RootBeanDefinition> channelProcessors = new ManagedList<RootBeanDefinition>(3);
        RootBeanDefinition secureChannelProcessor = new RootBeanDefinition(SecureChannelProcessor.class);
        RootBeanDefinition retryWithHttp = new RootBeanDefinition(RetryWithHttpEntryPoint.class);
        RootBeanDefinition retryWithHttps = new RootBeanDefinition(RetryWithHttpsEntryPoint.class);
        RuntimeBeanReference portMapper = new RuntimeBeanReference(portMapperBeanName);
        retryWithHttp.getPropertyValues().addPropertyValue("portMapper", portMapper);
        retryWithHttps.getPropertyValues().addPropertyValue("portMapper", portMapper);
        secureChannelProcessor.getPropertyValues().addPropertyValue("entryPoint", retryWithHttps);
        RootBeanDefinition inSecureChannelProcessor = new RootBeanDefinition(InsecureChannelProcessor.class);
        inSecureChannelProcessor.getPropertyValues().addPropertyValue("entryPoint", retryWithHttp);
        channelProcessors.add(secureChannelProcessor);
        channelProcessors.add(inSecureChannelProcessor);
        channelDecisionManager.getPropertyValues().addPropertyValue("channelProcessors", channelProcessors);

        String id = pc.getReaderContext().registerWithGeneratedName(channelDecisionManager);
        channelFilter.getPropertyValues().addPropertyValue("channelDecisionManager", new RuntimeBeanReference(id));
        return channelFilter;
    }

    private RootBeanDefinition createSessionFixationProtectionFilter(ParserContext pc, String sessionFixationAttribute,
            BeanReference sessionRegistryRef) {
        if(!StringUtils.hasText(sessionFixationAttribute)) {
            sessionFixationAttribute = OPT_SESSION_FIXATION_MIGRATE_SESSION;
        }

        if (!sessionFixationAttribute.equals(OPT_SESSION_FIXATION_NO_PROTECTION)) {
            BeanDefinitionBuilder sessionFixationFilter =
                BeanDefinitionBuilder.rootBeanDefinition(SessionFixationProtectionFilter.class);
            sessionFixationFilter.addPropertyValue("migrateSessionAttributes",
                    Boolean.valueOf(sessionFixationAttribute.equals(OPT_SESSION_FIXATION_MIGRATE_SESSION)));
            if (sessionRegistryRef != null) {
                sessionFixationFilter.addPropertyValue("sessionRegistry", sessionRegistryRef);
            }
            return (RootBeanDefinition) sessionFixationFilter.getBeanDefinition();
        }
        return null;
    }

    private FilterAndEntryPoint createFormLoginFilter(Element element, ParserContext pc, boolean autoConfig,
            boolean allowSessionCreation, RootBeanDefinition sfpf, BeanReference authManager) {
        RootBeanDefinition formLoginFilter = null;
        RootBeanDefinition formLoginEntryPoint = null;

        Element formLoginElt = DomUtils.getChildElementByTagName(element, Elements.FORM_LOGIN);

        if (formLoginElt != null || autoConfig) {
            FormLoginBeanDefinitionParser parser = new FormLoginBeanDefinitionParser("/j_spring_security_check",
                    AUTHENTICATION_PROCESSING_FILTER_CLASS);

            parser.parse(formLoginElt, pc, sfpf);
            formLoginFilter = parser.getFilterBean();
            formLoginEntryPoint = parser.getEntryPointBean();
        }

        if (formLoginFilter != null) {
            formLoginFilter.getPropertyValues().addPropertyValue("allowSessionCreation", new Boolean(allowSessionCreation));
            formLoginFilter.getPropertyValues().addPropertyValue("authenticationManager", authManager);
        }

        return new FilterAndEntryPoint(formLoginFilter, formLoginEntryPoint);
    }

    private FilterAndEntryPoint createOpenIDLoginFilter(Element element, ParserContext pc, boolean autoConfig,
            boolean allowSessionCreation, RootBeanDefinition sfpf, BeanReference authManager) {
        Element openIDLoginElt = DomUtils.getChildElementByTagName(element, Elements.OPENID_LOGIN);
        RootBeanDefinition openIDFilter = null;
        RootBeanDefinition openIDEntryPoint = null;

        if (openIDLoginElt != null) {
            FormLoginBeanDefinitionParser parser = new FormLoginBeanDefinitionParser("/j_spring_openid_security_check",
                    OPEN_ID_AUTHENTICATION_PROCESSING_FILTER_CLASS);

            parser.parse(openIDLoginElt, pc, sfpf);
            openIDFilter = parser.getFilterBean();
            openIDEntryPoint = parser.getEntryPointBean();
        }

        if (openIDFilter != null) {
            openIDFilter.getPropertyValues().addPropertyValue("allowSessionCreation", new Boolean(allowSessionCreation));
            openIDFilter.getPropertyValues().addPropertyValue("authenticationManager", authManager);
        }

        return new FilterAndEntryPoint(openIDFilter, openIDEntryPoint);
    }

    private BeanReference createOpenIDProvider(Element elt, ParserContext pc) {
        Element openIDLoginElt = DomUtils.getChildElementByTagName(elt, Elements.OPENID_LOGIN);
        BeanDefinitionBuilder openIDProviderBuilder =
            BeanDefinitionBuilder.rootBeanDefinition(OPEN_ID_AUTHENTICATION_PROVIDER_CLASS);

        String userService = openIDLoginElt.getAttribute(ATT_USER_SERVICE_REF);

        if (StringUtils.hasText(userService)) {
            openIDProviderBuilder.addPropertyReference("userDetailsService", userService);
        }

        BeanDefinition openIDProvider = openIDProviderBuilder.getBeanDefinition();
        String id = pc.getReaderContext().registerWithGeneratedName(openIDProvider);
        return new RuntimeBeanReference(id);
    }

    class FilterAndEntryPoint {
        RootBeanDefinition filter;
        RootBeanDefinition entryPoint;

        public FilterAndEntryPoint(RootBeanDefinition filter, RootBeanDefinition entryPoint) {
            this.filter = filter;
            this.entryPoint = entryPoint;
        }
    }

    private BeanMetadataElement selectEntryPoint(Element element, ParserContext pc, FilterAndEntryPoint basic, FilterAndEntryPoint form, FilterAndEntryPoint openID, FilterAndEntryPoint x509) {
        // We need to establish the main entry point.
        // First check if a custom entry point bean is set
        String customEntryPoint = element.getAttribute(ATT_ENTRY_POINT_REF);

        if (StringUtils.hasText(customEntryPoint)) {
//            pc.getRegistry().registerAlias(customEntryPoint, BeanIds.MAIN_ENTRY_POINT);
            return new RuntimeBeanReference(customEntryPoint);
        }

        Element basicAuthElt = DomUtils.getChildElementByTagName(element, Elements.BASIC_AUTH);
        Element formLoginElt = DomUtils.getChildElementByTagName(element, Elements.FORM_LOGIN);
        Element openIDLoginElt = DomUtils.getChildElementByTagName(element, Elements.OPENID_LOGIN);
        // Basic takes precedence if explicit element is used and no others are configured
        if (basicAuthElt != null && formLoginElt == null && openIDLoginElt == null) {
            //pc.getRegistry().registerAlias(BeanIds.BASIC_AUTHENTICATION_ENTRY_POINT, BeanIds.MAIN_ENTRY_POINT);
            return basic.entryPoint;
        }

        // If formLogin has been enabled either through an element or auto-config, then it is used if no openID login page
        // has been set
        String openIDLoginPage = getLoginFormUrl(openID.entryPoint);

        if (form.filter != null && openIDLoginPage == null) {
            //pc.getRegistry().registerAlias(BeanIds.FORM_LOGIN_ENTRY_POINT, BeanIds.MAIN_ENTRY_POINT);
            return form.entryPoint;
        }

        // Otherwise use OpenID if enabled
        if (openID.filter != null && form.filter == null) {
            //pc.getRegistry().registerAlias(BeanIds.OPEN_ID_ENTRY_POINT, BeanIds.MAIN_ENTRY_POINT);
            return openID.entryPoint;
        }

        // If X.509 has been enabled, use the preauth entry point.
        if (DomUtils.getChildElementByTagName(element, Elements.X509) != null) {
            //pc.getRegistry().registerAlias(BeanIds.PRE_AUTH_ENTRY_POINT, BeanIds.MAIN_ENTRY_POINT);
            return x509.entryPoint;
        }

        pc.getReaderContext().error("No AuthenticationEntryPoint could be established. Please " +
                "make sure you have a login mechanism configured through the namespace (such as form-login) or " +
                "specify a custom AuthenticationEntryPoint with the '" + ATT_ENTRY_POINT_REF+ "' attribute ",
                pc.extractSource(element));
        return null;
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
    void parseInterceptUrlsForChannelSecurityAndEmptyFilterChains(List<Element> urlElts, Map<String, List<BeanMetadataElement>> filterChainMap,  Map<RequestKey, List<ConfigAttribute>> channelRequestMap,
            boolean useLowerCasePaths, ParserContext parserContext) {

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

                channelRequestMap.put(new RequestKey(path),
                        SecurityConfig.createList((StringUtils.commaDelimitedListToStringArray(channelConfigAttribute))));
            }

            String filters = urlElt.getAttribute(ATT_FILTERS);

            if (StringUtils.hasText(filters)) {
                if (!filters.equals(OPT_FILTERS_NONE)) {
                    parserContext.getReaderContext().error("Currently only 'none' is supported as the custom " +
                            "filters attribute", urlElt);
                }

                List<BeanMetadataElement> noFilters = Collections.emptyList();
                filterChainMap.put(path, noFilters);
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
