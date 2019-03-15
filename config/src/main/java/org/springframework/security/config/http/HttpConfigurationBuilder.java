/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.http;

import static org.springframework.security.config.http.HttpSecurityBeanDefinitionParser.*;
import static org.springframework.security.config.http.SecurityFilters.*;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.Elements;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.channel.InsecureChannelProcessor;
import org.springframework.security.web.access.channel.RetryWithHttpEntryPoint;
import org.springframework.security.web.access.channel.RetryWithHttpsEntryPoint;
import org.springframework.security.web.access.channel.SecureChannelProcessor;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Stateful class which helps HttpSecurityBDP to create the configuration for the &lt;http&gt; element.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.0
 */
class HttpConfigurationBuilder {
    private static final String ATT_CREATE_SESSION = "create-session";

    private static final String ATT_SESSION_FIXATION_PROTECTION = "session-fixation-protection";
    private static final String OPT_SESSION_FIXATION_NO_PROTECTION = "none";
    private static final String OPT_SESSION_FIXATION_MIGRATE_SESSION = "migrateSession";
    private static final String OPT_CHANGE_SESSION_ID = "changeSessionId";

    private static final String ATT_INVALID_SESSION_URL = "invalid-session-url";
    private static final String ATT_SESSION_AUTH_STRATEGY_REF = "session-authentication-strategy-ref";
    private static final String ATT_SESSION_AUTH_ERROR_URL = "session-authentication-error-url";
    private static final String ATT_SECURITY_CONTEXT_REPOSITORY = "security-context-repository-ref";

    private static final String ATT_DISABLE_URL_REWRITING = "disable-url-rewriting";

    private static final String ATT_ACCESS_MGR = "access-decision-manager-ref";
    private static final String ATT_ONCE_PER_REQUEST = "once-per-request";

    private static final String ATT_REF = "ref";

    private final Element httpElt;
    private final ParserContext pc;
    private final SessionCreationPolicy sessionPolicy;
    private final List<Element> interceptUrls;
    private final MatcherType matcherType;

    private BeanDefinition cpf;
    private BeanDefinition securityContextPersistenceFilter;
    private BeanReference contextRepoRef;
    private BeanReference sessionRegistryRef;
    private BeanDefinition concurrentSessionFilter;
    private BeanDefinition webAsyncManagerFilter;
    private BeanDefinition requestCacheAwareFilter;
    private BeanReference sessionStrategyRef;
    private RootBeanDefinition sfpf;
    private BeanDefinition servApiFilter;
    private BeanDefinition jaasApiFilter;
    private final BeanReference portMapper;
    private final BeanReference portResolver;
    private BeanReference fsi;
    private BeanReference requestCache;
    private BeanDefinition addHeadersFilter;
    private BeanDefinition csrfFilter;
    private BeanMetadataElement csrfLogoutHandler;
    private BeanMetadataElement csrfAuthStrategy;

    private CsrfBeanDefinitionParser csrfParser;

    private BeanDefinition invalidSession;

    public HttpConfigurationBuilder(Element element, ParserContext pc,
            BeanReference portMapper, BeanReference portResolver, BeanReference authenticationManager) {
        this.httpElt = element;
        this.pc = pc;
        this.portMapper = portMapper;
        this.portResolver = portResolver;
        this.matcherType = MatcherType.fromElement(element);
        interceptUrls = DomUtils.getChildElementsByTagName(element, Elements.INTERCEPT_URL);

        for (Element urlElt : interceptUrls) {
            if (StringUtils.hasText(urlElt.getAttribute(ATT_FILTERS))) {
                pc.getReaderContext().error("The use of \"filters='none'\" is no longer supported. Please define a" +
                        " separate <http> element for the pattern you want to exclude and use the attribute" +
                        " \"security='none'\".", pc.extractSource(urlElt));
            }
        }

        String createSession = element.getAttribute(ATT_CREATE_SESSION);

        if (StringUtils.hasText(createSession)) {
            sessionPolicy = createPolicy(createSession);
        } else {
            sessionPolicy = SessionCreationPolicy.IF_REQUIRED;
        }

        createCsrfFilter();
        createSecurityContextPersistenceFilter();
        createSessionManagementFilters();
        createWebAsyncManagerFilter();
        createRequestCacheFilter();
        createServletApiFilter(authenticationManager);
        createJaasApiFilter();
        createChannelProcessingFilter();
        createFilterSecurityInterceptor(authenticationManager);
        createAddHeadersFilter();
    }

    private SessionCreationPolicy createPolicy(String createSession) {
        if("ifRequired".equals(createSession)) {
            return SessionCreationPolicy.IF_REQUIRED;
        } else if("always".equals(createSession)) {
            return SessionCreationPolicy.ALWAYS;
        } else if("never".equals(createSession)) {
            return SessionCreationPolicy.NEVER;
        } else if("stateless".equals(createSession)) {
            return SessionCreationPolicy.STATELESS;
        }

        throw new IllegalStateException("Cannot convert " + createSession + " to " + SessionCreationPolicy.class.getName());
    }

    @SuppressWarnings("rawtypes")
    void setLogoutHandlers(ManagedList logoutHandlers) {
        if(logoutHandlers != null) {
            if(concurrentSessionFilter != null) {
                concurrentSessionFilter.getPropertyValues().add("logoutHandlers", logoutHandlers);
            }
            if(servApiFilter != null) {
                servApiFilter.getPropertyValues().add("logoutHandlers", logoutHandlers);
            }
        }
    }

    void setEntryPoint(BeanMetadataElement entryPoint) {
        if(servApiFilter != null) {
            servApiFilter.getPropertyValues().add("authenticationEntryPoint", entryPoint);
        }
    }

    void setAccessDeniedHandler(BeanMetadataElement accessDeniedHandler) {
        if(csrfParser != null ) {
            csrfParser.initAccessDeniedHandler(this.invalidSession, accessDeniedHandler);
        }
    }

    // Needed to account for placeholders
    static String createPath(String path, boolean lowerCase) {
        return lowerCase ? path.toLowerCase() : path;
    }

    private void createSecurityContextPersistenceFilter() {
        BeanDefinitionBuilder scpf = BeanDefinitionBuilder.rootBeanDefinition(SecurityContextPersistenceFilter.class);

        String repoRef = httpElt.getAttribute(ATT_SECURITY_CONTEXT_REPOSITORY);
        String disableUrlRewriting = httpElt.getAttribute(ATT_DISABLE_URL_REWRITING);

        if (StringUtils.hasText(repoRef)) {
            if (sessionPolicy == SessionCreationPolicy.ALWAYS) {
                scpf.addPropertyValue("forceEagerSessionCreation", Boolean.TRUE);
            }
        } else {
            BeanDefinitionBuilder contextRepo;
            if (sessionPolicy == SessionCreationPolicy.STATELESS) {
                contextRepo = BeanDefinitionBuilder.rootBeanDefinition(NullSecurityContextRepository.class);
            } else {
                contextRepo = BeanDefinitionBuilder.rootBeanDefinition(HttpSessionSecurityContextRepository.class);
                switch (sessionPolicy) {
                    case ALWAYS:
                        contextRepo.addPropertyValue("allowSessionCreation", Boolean.TRUE);
                        scpf.addPropertyValue("forceEagerSessionCreation", Boolean.TRUE);
                        break;
                    case NEVER:
                        contextRepo.addPropertyValue("allowSessionCreation", Boolean.FALSE);
                        scpf.addPropertyValue("forceEagerSessionCreation", Boolean.FALSE);
                        break;
                    default:
                        contextRepo.addPropertyValue("allowSessionCreation", Boolean.TRUE);
                        scpf.addPropertyValue("forceEagerSessionCreation", Boolean.FALSE);
                }

                if ("true".equals(disableUrlRewriting)) {
                    contextRepo.addPropertyValue("disableUrlRewriting", Boolean.TRUE);
                }
            }

            BeanDefinition repoBean = contextRepo.getBeanDefinition();
            repoRef = pc.getReaderContext().generateBeanName(repoBean);
            pc.registerBeanComponent(new BeanComponentDefinition(repoBean, repoRef));
        }

        contextRepoRef = new RuntimeBeanReference(repoRef);
        scpf.addConstructorArgValue(contextRepoRef);

        securityContextPersistenceFilter = scpf.getBeanDefinition();
    }

    private void createSessionManagementFilters() {
        Element sessionMgmtElt = DomUtils.getChildElementByTagName(httpElt, Elements.SESSION_MANAGEMENT);
        Element sessionCtrlElt = null;

        String sessionFixationAttribute = null;
        String invalidSessionUrl = null;
        String sessionAuthStratRef = null;
        String errorUrl = null;

        boolean sessionControlEnabled = false;
        if (sessionMgmtElt != null) {
            if (sessionPolicy == SessionCreationPolicy.STATELESS) {
                pc.getReaderContext().error(Elements.SESSION_MANAGEMENT + "  cannot be used" +
                        " in combination with " + ATT_CREATE_SESSION + "='"+ SessionCreationPolicy.STATELESS +"'",
                        pc.extractSource(sessionMgmtElt));
            }
            sessionFixationAttribute = sessionMgmtElt.getAttribute(ATT_SESSION_FIXATION_PROTECTION);
            invalidSessionUrl = sessionMgmtElt.getAttribute(ATT_INVALID_SESSION_URL);
            sessionAuthStratRef = sessionMgmtElt.getAttribute(ATT_SESSION_AUTH_STRATEGY_REF);
            errorUrl = sessionMgmtElt.getAttribute(ATT_SESSION_AUTH_ERROR_URL);
            sessionCtrlElt = DomUtils.getChildElementByTagName(sessionMgmtElt, Elements.CONCURRENT_SESSIONS);
            sessionControlEnabled =  sessionCtrlElt != null;

            if (sessionControlEnabled) {
                if (StringUtils.hasText(sessionAuthStratRef)) {
                    pc.getReaderContext().error(ATT_SESSION_AUTH_STRATEGY_REF + " attribute cannot be used" +
                            " in combination with <" + Elements.CONCURRENT_SESSIONS + ">", pc.extractSource(sessionCtrlElt));
                }
                createConcurrencyControlFilterAndSessionRegistry(sessionCtrlElt);
            }
        }

        if (!StringUtils.hasText(sessionFixationAttribute)) {
             Method changeSessionIdMethod = ReflectionUtils.findMethod(HttpServletRequest.class, "changeSessionId");
            sessionFixationAttribute = changeSessionIdMethod == null ? OPT_SESSION_FIXATION_MIGRATE_SESSION : OPT_CHANGE_SESSION_ID;
        } else if (StringUtils.hasText(sessionAuthStratRef)) {
            pc.getReaderContext().error(ATT_SESSION_FIXATION_PROTECTION + " attribute cannot be used" +
                    " in combination with " + ATT_SESSION_AUTH_STRATEGY_REF, pc.extractSource(sessionMgmtElt));
        }

        if (sessionPolicy == SessionCreationPolicy.STATELESS) {
            // SEC-1424: do nothing
            return;
        }

        boolean sessionFixationProtectionRequired = !sessionFixationAttribute.equals(OPT_SESSION_FIXATION_NO_PROTECTION);

        ManagedList<BeanMetadataElement> delegateSessionStrategies = new ManagedList<BeanMetadataElement>();
        BeanDefinitionBuilder concurrentSessionStrategy;
        BeanDefinitionBuilder sessionFixationStrategy = null;
        BeanDefinitionBuilder registerSessionStrategy;

        if(csrfAuthStrategy != null) {
            delegateSessionStrategies.add(csrfAuthStrategy);
        }

        if (sessionControlEnabled) {
            assert sessionRegistryRef != null;
            concurrentSessionStrategy = BeanDefinitionBuilder.rootBeanDefinition(ConcurrentSessionControlAuthenticationStrategy.class);
            concurrentSessionStrategy.addConstructorArgValue(sessionRegistryRef);

            String maxSessions = sessionCtrlElt.getAttribute("max-sessions");

            if (StringUtils.hasText(maxSessions)) {
                concurrentSessionStrategy.addPropertyValue("maximumSessions", maxSessions);
            }

            String exceptionIfMaximumExceeded = sessionCtrlElt.getAttribute("error-if-maximum-exceeded");

            if (StringUtils.hasText(exceptionIfMaximumExceeded)) {
                concurrentSessionStrategy.addPropertyValue("exceptionIfMaximumExceeded", exceptionIfMaximumExceeded);
            }
            delegateSessionStrategies.add(concurrentSessionStrategy.getBeanDefinition());
        }
        boolean useChangeSessionId = OPT_CHANGE_SESSION_ID.equals(sessionFixationAttribute);
        if (sessionFixationProtectionRequired || StringUtils.hasText(invalidSessionUrl)) {
            if(useChangeSessionId) {
                sessionFixationStrategy = BeanDefinitionBuilder.rootBeanDefinition(ChangeSessionIdAuthenticationStrategy.class);
            } else {
                sessionFixationStrategy = BeanDefinitionBuilder.rootBeanDefinition(SessionFixationProtectionStrategy.class);
            }
            delegateSessionStrategies.add(sessionFixationStrategy.getBeanDefinition());
        }

        if(StringUtils.hasText(sessionAuthStratRef)) {
            delegateSessionStrategies.add(new RuntimeBeanReference(sessionAuthStratRef));
        }

        if(sessionControlEnabled) {
            registerSessionStrategy = BeanDefinitionBuilder.rootBeanDefinition(RegisterSessionAuthenticationStrategy.class);
            registerSessionStrategy.addConstructorArgValue(sessionRegistryRef);
            delegateSessionStrategies.add(registerSessionStrategy.getBeanDefinition());
        }

        if(delegateSessionStrategies.isEmpty()) {
            sfpf = null;
            return;
        }

        BeanDefinitionBuilder sessionMgmtFilter = BeanDefinitionBuilder.rootBeanDefinition(SessionManagementFilter.class);
        RootBeanDefinition failureHandler = new RootBeanDefinition(SimpleUrlAuthenticationFailureHandler.class);
        if (StringUtils.hasText(errorUrl)) {
            failureHandler.getPropertyValues().addPropertyValue("defaultFailureUrl", errorUrl);
        }
        sessionMgmtFilter.addPropertyValue("authenticationFailureHandler", failureHandler);
        sessionMgmtFilter.addConstructorArgValue(contextRepoRef);

        if (!StringUtils.hasText(sessionAuthStratRef) && sessionFixationStrategy != null && !useChangeSessionId ) {

            if (sessionFixationProtectionRequired) {
                sessionFixationStrategy.addPropertyValue("migrateSessionAttributes",
                        Boolean.valueOf(sessionFixationAttribute.equals(OPT_SESSION_FIXATION_MIGRATE_SESSION)));
            }
        }

        if(!delegateSessionStrategies.isEmpty()) {
            BeanDefinitionBuilder sessionStrategy = BeanDefinitionBuilder.rootBeanDefinition(CompositeSessionAuthenticationStrategy.class);
            BeanDefinition strategyBean = sessionStrategy.getBeanDefinition();
            sessionStrategy.addConstructorArgValue(delegateSessionStrategies);
            sessionAuthStratRef = pc.getReaderContext().generateBeanName(strategyBean);
            pc.registerBeanComponent(new BeanComponentDefinition(strategyBean, sessionAuthStratRef));

        }

        if (StringUtils.hasText(invalidSessionUrl)) {
            BeanDefinitionBuilder invalidSessionBldr = BeanDefinitionBuilder.rootBeanDefinition(SimpleRedirectInvalidSessionStrategy.class);
            invalidSessionBldr.addConstructorArgValue(invalidSessionUrl);
            invalidSession = invalidSessionBldr.getBeanDefinition();
            sessionMgmtFilter.addPropertyValue("invalidSessionStrategy", invalidSession);
        }

        sessionMgmtFilter.addConstructorArgReference(sessionAuthStratRef);

        sfpf = (RootBeanDefinition) sessionMgmtFilter.getBeanDefinition();
        sessionStrategyRef = new RuntimeBeanReference(sessionAuthStratRef);
    }

    private void createConcurrencyControlFilterAndSessionRegistry(Element element) {
        final String ATT_EXPIRY_URL = "expired-url";
        final String ATT_SESSION_REGISTRY_ALIAS = "session-registry-alias";
        final String ATT_SESSION_REGISTRY_REF = "session-registry-ref";

        CompositeComponentDefinition compositeDef =
            new CompositeComponentDefinition(element.getTagName(), pc.extractSource(element));
        pc.pushContainingComponent(compositeDef);

        BeanDefinitionRegistry beanRegistry = pc.getRegistry();

        String sessionRegistryId = element.getAttribute(ATT_SESSION_REGISTRY_REF);

        if (!StringUtils.hasText(sessionRegistryId)) {
            // Register an internal SessionRegistryImpl if no external reference supplied.
            RootBeanDefinition sessionRegistry = new RootBeanDefinition(SessionRegistryImpl.class);
            sessionRegistryId = pc.getReaderContext().registerWithGeneratedName(sessionRegistry);
            pc.registerComponent(new BeanComponentDefinition(sessionRegistry, sessionRegistryId));
        }

        String registryAlias = element.getAttribute(ATT_SESSION_REGISTRY_ALIAS);
        if (StringUtils.hasText(registryAlias)) {
            beanRegistry.registerAlias(sessionRegistryId, registryAlias);
        }

        BeanDefinitionBuilder filterBuilder =
                BeanDefinitionBuilder.rootBeanDefinition(ConcurrentSessionFilter.class);
        filterBuilder.addConstructorArgReference(sessionRegistryId);

        Object source = pc.extractSource(element);
        filterBuilder.getRawBeanDefinition().setSource(source);
        filterBuilder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);

        String expiryUrl = element.getAttribute(ATT_EXPIRY_URL);

        if (StringUtils.hasText(expiryUrl)) {
            WebConfigUtils.validateHttpRedirect(expiryUrl, pc, source);
            filterBuilder.addConstructorArgValue(expiryUrl);
        }

        pc.popAndRegisterContainingComponent();

        concurrentSessionFilter = filterBuilder.getBeanDefinition();
        sessionRegistryRef = new RuntimeBeanReference(sessionRegistryId);
    }

    private void createWebAsyncManagerFilter() {
        boolean asyncSupported = ClassUtils.hasMethod(ServletRequest.class, "startAsync");
        if(asyncSupported) {
            webAsyncManagerFilter = new RootBeanDefinition(WebAsyncManagerIntegrationFilter.class);
        }
    }

    // Adds the servlet-api integration filter if required
    private void createServletApiFilter(BeanReference authenticationManager) {
        final String ATT_SERVLET_API_PROVISION = "servlet-api-provision";
        final String DEF_SERVLET_API_PROVISION = "true";

        String provideServletApi = httpElt.getAttribute(ATT_SERVLET_API_PROVISION);
        if (!StringUtils.hasText(provideServletApi)) {
            provideServletApi = DEF_SERVLET_API_PROVISION;
        }

        if ("true".equals(provideServletApi)) {
            servApiFilter = new RootBeanDefinition(SecurityContextHolderAwareRequestFilter.class);
            servApiFilter.getPropertyValues().add("authenticationManager", authenticationManager);
        }
    }

    // Adds the jaas-api integration filter if required
    private void createJaasApiFilter() {
        final String ATT_JAAS_API_PROVISION = "jaas-api-provision";
        final String DEF_JAAS_API_PROVISION = "false";

        String provideJaasApi = httpElt.getAttribute(ATT_JAAS_API_PROVISION);
        if (!StringUtils.hasText(provideJaasApi)) {
            provideJaasApi = DEF_JAAS_API_PROVISION;
        }

        if ("true".equals(provideJaasApi)) {
            jaasApiFilter = new RootBeanDefinition(JaasApiIntegrationFilter.class);
        }
    }

    private void createChannelProcessingFilter() {
        ManagedMap<BeanDefinition,BeanDefinition> channelRequestMap = parseInterceptUrlsForChannelSecurity();

        if (channelRequestMap.isEmpty()) {
            return;
        }

        RootBeanDefinition channelFilter = new RootBeanDefinition(ChannelProcessingFilter.class);
        BeanDefinitionBuilder metadataSourceBldr = BeanDefinitionBuilder.rootBeanDefinition(DefaultFilterInvocationSecurityMetadataSource.class);
        metadataSourceBldr.addConstructorArgValue(channelRequestMap);
//        metadataSourceBldr.addPropertyValue("stripQueryStringFromUrls", matcher instanceof AntUrlPathMatcher);

        channelFilter.getPropertyValues().addPropertyValue("securityMetadataSource", metadataSourceBldr.getBeanDefinition());
        RootBeanDefinition channelDecisionManager = new RootBeanDefinition(ChannelDecisionManagerImpl.class);
        ManagedList<RootBeanDefinition> channelProcessors = new ManagedList<RootBeanDefinition>(3);
        RootBeanDefinition secureChannelProcessor = new RootBeanDefinition(SecureChannelProcessor.class);
        RootBeanDefinition retryWithHttp = new RootBeanDefinition(RetryWithHttpEntryPoint.class);
        RootBeanDefinition retryWithHttps = new RootBeanDefinition(RetryWithHttpsEntryPoint.class);

        retryWithHttp.getPropertyValues().addPropertyValue("portMapper", portMapper);
        retryWithHttp.getPropertyValues().addPropertyValue("portResolver", portResolver);
        retryWithHttps.getPropertyValues().addPropertyValue("portMapper", portMapper);
        retryWithHttps.getPropertyValues().addPropertyValue("portResolver", portResolver);
        secureChannelProcessor.getPropertyValues().addPropertyValue("entryPoint", retryWithHttps);
        RootBeanDefinition inSecureChannelProcessor = new RootBeanDefinition(InsecureChannelProcessor.class);
        inSecureChannelProcessor.getPropertyValues().addPropertyValue("entryPoint", retryWithHttp);
        channelProcessors.add(secureChannelProcessor);
        channelProcessors.add(inSecureChannelProcessor);
        channelDecisionManager.getPropertyValues().addPropertyValue("channelProcessors", channelProcessors);

        String id = pc.getReaderContext().registerWithGeneratedName(channelDecisionManager);
        channelFilter.getPropertyValues().addPropertyValue("channelDecisionManager", new RuntimeBeanReference(id));
        cpf = channelFilter;
    }

    /**
     * Parses the intercept-url elements to obtain the map used by channel security.
     * This will be empty unless the <tt>requires-channel</tt> attribute has been used on a URL path.
     */
    private ManagedMap<BeanDefinition,BeanDefinition> parseInterceptUrlsForChannelSecurity() {

        ManagedMap<BeanDefinition, BeanDefinition> channelRequestMap = new ManagedMap<BeanDefinition, BeanDefinition>();

        for (Element urlElt : interceptUrls) {
            String path = urlElt.getAttribute(ATT_PATH_PATTERN);
            String method = urlElt.getAttribute(ATT_HTTP_METHOD);

            if(!StringUtils.hasText(path)) {
                pc.getReaderContext().error("pattern attribute cannot be empty or null", urlElt);
            }

            String requiredChannel = urlElt.getAttribute(ATT_REQUIRES_CHANNEL);

            if (StringUtils.hasText(requiredChannel)) {
                BeanDefinition matcher = matcherType.createMatcher(path, method);

                RootBeanDefinition channelAttributes = new RootBeanDefinition(ChannelAttributeFactory.class);
                channelAttributes.getConstructorArgumentValues().addGenericArgumentValue(requiredChannel);
                channelAttributes.setFactoryMethodName("createChannelAttributes");

                channelRequestMap.put(matcher, channelAttributes);
            }
        }

        return channelRequestMap;
    }

    private void createRequestCacheFilter() {
        Element requestCacheElt = DomUtils.getChildElementByTagName(httpElt, Elements.REQUEST_CACHE);

        if (requestCacheElt != null) {
            requestCache = new RuntimeBeanReference(requestCacheElt.getAttribute(ATT_REF));
        } else {
            BeanDefinitionBuilder requestCacheBldr;

            if (sessionPolicy == SessionCreationPolicy.STATELESS) {
                requestCacheBldr = BeanDefinitionBuilder.rootBeanDefinition(NullRequestCache.class);
            } else {
                requestCacheBldr = BeanDefinitionBuilder.rootBeanDefinition(HttpSessionRequestCache.class);
                requestCacheBldr.addPropertyValue("createSessionAllowed", sessionPolicy == SessionCreationPolicy.IF_REQUIRED);
                requestCacheBldr.addPropertyValue("portResolver", portResolver);
                if(csrfFilter != null) {
                    BeanDefinitionBuilder requestCacheMatcherBldr = BeanDefinitionBuilder.rootBeanDefinition(AntPathRequestMatcher.class);
                    requestCacheMatcherBldr.addConstructorArgValue("/**");
                    requestCacheMatcherBldr.addConstructorArgValue("GET");
                    requestCacheBldr.addPropertyValue("requestMatcher", requestCacheMatcherBldr.getBeanDefinition());
                }
            }

            BeanDefinition bean = requestCacheBldr.getBeanDefinition();
            String id = pc.getReaderContext().generateBeanName(bean);
            pc.registerBeanComponent(new BeanComponentDefinition(bean, id));

            this.requestCache = new RuntimeBeanReference(id);
        }

        requestCacheAwareFilter = new RootBeanDefinition(RequestCacheAwareFilter.class);
        requestCacheAwareFilter.getConstructorArgumentValues().addGenericArgumentValue(requestCache);
    }

    private void createFilterSecurityInterceptor(BeanReference authManager) {
        boolean useExpressions = FilterInvocationSecurityMetadataSourceParser.isUseExpressions(httpElt);
        RootBeanDefinition securityMds = FilterInvocationSecurityMetadataSourceParser.createSecurityMetadataSource(interceptUrls, httpElt, pc);

        RootBeanDefinition accessDecisionMgr;
        ManagedList<BeanDefinition> voters =  new ManagedList<BeanDefinition>(2);

        if (useExpressions) {
            BeanDefinitionBuilder expressionVoter = BeanDefinitionBuilder.rootBeanDefinition(WebExpressionVoter.class);
            // Read the expression handler from the FISMS
            RuntimeBeanReference expressionHandler = (RuntimeBeanReference)
                    securityMds.getConstructorArgumentValues().getArgumentValue(1, RuntimeBeanReference.class).getValue();

            expressionVoter.addPropertyValue("expressionHandler", expressionHandler);

            voters.add(expressionVoter.getBeanDefinition());
        } else {
            voters.add(new RootBeanDefinition(RoleVoter.class));
            voters.add(new RootBeanDefinition(AuthenticatedVoter.class));
        }
        accessDecisionMgr = new RootBeanDefinition(AffirmativeBased.class);
        accessDecisionMgr.getConstructorArgumentValues().addGenericArgumentValue(voters);
        accessDecisionMgr.setSource(pc.extractSource(httpElt));

        // Set up the access manager reference for http
        String accessManagerId = httpElt.getAttribute(ATT_ACCESS_MGR);

        if (!StringUtils.hasText(accessManagerId)) {
            accessManagerId = pc.getReaderContext().generateBeanName(accessDecisionMgr);
            pc.registerBeanComponent(new BeanComponentDefinition(accessDecisionMgr, accessManagerId));
        }

        BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(FilterSecurityInterceptor.class);

        builder.addPropertyReference("accessDecisionManager", accessManagerId);
        builder.addPropertyValue("authenticationManager", authManager);

        if ("false".equals(httpElt.getAttribute(ATT_ONCE_PER_REQUEST))) {
            builder.addPropertyValue("observeOncePerRequest", Boolean.FALSE);
        }

        builder.addPropertyValue("securityMetadataSource", securityMds);
        BeanDefinition fsiBean = builder.getBeanDefinition();
        String fsiId = pc.getReaderContext().generateBeanName(fsiBean);
        pc.registerBeanComponent(new BeanComponentDefinition(fsiBean,fsiId));

        // Create and register a DefaultWebInvocationPrivilegeEvaluator for use with taglibs etc.
        BeanDefinition wipe = new RootBeanDefinition(DefaultWebInvocationPrivilegeEvaluator.class);
        wipe.getConstructorArgumentValues().addGenericArgumentValue(new RuntimeBeanReference(fsiId));

        pc.registerBeanComponent(new BeanComponentDefinition(wipe, pc.getReaderContext().generateBeanName(wipe)));

        this.fsi = new RuntimeBeanReference(fsiId);
    }

    private void createAddHeadersFilter() {
        Element elmt = DomUtils.getChildElementByTagName(httpElt, Elements.HEADERS);
        if (elmt != null) {
            this.addHeadersFilter = new HeadersBeanDefinitionParser().parse(elmt, pc);
        }

    }

    private CsrfBeanDefinitionParser createCsrfFilter() {
        Element elmt = DomUtils.getChildElementByTagName(httpElt, Elements.CSRF);
        if (elmt != null) {
            csrfParser = new CsrfBeanDefinitionParser();
            csrfFilter = csrfParser.parse(elmt, pc);
            this.csrfAuthStrategy = csrfParser.getCsrfAuthenticationStrategy();
            this.csrfLogoutHandler = csrfParser.getCsrfLogoutHandler();
            return csrfParser;
        }
        return null;
    }

    BeanMetadataElement getCsrfLogoutHandler() {
        return this.csrfLogoutHandler;
    }

    BeanReference getSessionStrategy() {
        return sessionStrategyRef;
    }

    SessionCreationPolicy getSessionCreationPolicy() {
        return sessionPolicy;
    }

    BeanReference getRequestCache() {
        return requestCache;
    }

    List<OrderDecorator> getFilters() {
        List<OrderDecorator> filters = new ArrayList<OrderDecorator>();

        if (cpf != null) {
            filters.add(new OrderDecorator(cpf, CHANNEL_FILTER));
        }

        if (concurrentSessionFilter != null) {
            filters.add(new OrderDecorator(concurrentSessionFilter, CONCURRENT_SESSION_FILTER));
        }

        if (webAsyncManagerFilter != null) {
            filters.add(new OrderDecorator(webAsyncManagerFilter, WEB_ASYNC_MANAGER_FILTER));
        }

        filters.add(new OrderDecorator(securityContextPersistenceFilter, SECURITY_CONTEXT_FILTER));

        if (servApiFilter != null) {
            filters.add(new OrderDecorator(servApiFilter, SERVLET_API_SUPPORT_FILTER));
        }

        if (jaasApiFilter != null) {
            filters.add(new OrderDecorator(jaasApiFilter, JAAS_API_SUPPORT_FILTER));
        }

        if (sfpf != null) {
            filters.add(new OrderDecorator(sfpf, SESSION_MANAGEMENT_FILTER));
        }

        filters.add(new OrderDecorator(fsi, FILTER_SECURITY_INTERCEPTOR));

        if (sessionPolicy != SessionCreationPolicy.STATELESS) {
            filters.add(new OrderDecorator(requestCacheAwareFilter, REQUEST_CACHE_FILTER));
        }

        if (addHeadersFilter != null) {
            filters.add(new OrderDecorator(addHeadersFilter, HEADERS_FILTER));
        }

        if (csrfFilter != null) {
            filters.add(new OrderDecorator(csrfFilter, CSRF_FILTER));
        }

        return filters;
    }
}
