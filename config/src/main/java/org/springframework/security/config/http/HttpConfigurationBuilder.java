/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.ServletRequest;
import org.w3c.dom.Element;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
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
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.config.Elements;
import org.springframework.security.config.http.GrantedAuthorityDefaultsParserUtils.AbstractGrantedAuthorityDefaultsBeanFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.access.AuthorizationManagerWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.HandlerMappingIntrospectorRequestTransformer;
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
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.DisableEncodeUrlFilter;
import org.springframework.security.web.session.ForceEagerSessionCreationFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

/**
 * Stateful class which helps HttpSecurityBDP to create the configuration for the
 * &lt;http&gt; element.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.0
 */
class HttpConfigurationBuilder {

	private static final String HANDLER_MAPPING_INTROSPECTOR = "org.springframework.web.servlet.handler.HandlerMappingIntrospector";

	private static final boolean mvcPresent = ClassUtils.isPresent(HANDLER_MAPPING_INTROSPECTOR,
			HttpConfigurationBuilder.class.getClassLoader());

	private static final String ATT_CREATE_SESSION = "create-session";

	private static final String ATT_SESSION_FIXATION_PROTECTION = "session-fixation-protection";

	private static final String OPT_SESSION_FIXATION_NO_PROTECTION = "none";

	private static final String OPT_SESSION_FIXATION_MIGRATE_SESSION = "migrateSession";

	private static final String OPT_CHANGE_SESSION_ID = "changeSessionId";

	private static final String ATT_AUTHENTICATION_STRATEGY_EXPLICIT_INVOCATION = "authentication-strategy-explicit-invocation";

	private static final String ATT_INVALID_SESSION_URL = "invalid-session-url";

	private static final String ATT_OBSERVATION_REGISTRY_REF = "observation-registry-ref";

	private static final String ATT_SESSION_AUTH_STRATEGY_REF = "session-authentication-strategy-ref";

	private static final String ATT_SESSION_AUTH_ERROR_URL = "session-authentication-error-url";

	private static final String ATT_SECURITY_CONTEXT_HOLDER_STRATEGY = "security-context-holder-strategy-ref";

	private static final String ATT_SECURITY_CONTEXT_REPOSITORY = "security-context-repository-ref";

	private static final String ATT_SECURITY_CONTEXT_EXPLICIT_SAVE = "security-context-explicit-save";

	private static final String ATT_INVALID_SESSION_STRATEGY_REF = "invalid-session-strategy-ref";

	private static final String ATT_DISABLE_URL_REWRITING = "disable-url-rewriting";

	private static final String ATT_USE_AUTHORIZATION_MGR = "use-authorization-manager";

	private static final String ATT_AUTHORIZATION_MGR = "authorization-manager-ref";

	private static final String ATT_ACCESS_MGR = "access-decision-manager-ref";

	private static final String ATT_ONCE_PER_REQUEST = "once-per-request";

	private static final String ATT_REF = "ref";

	private static final String ATT_EXPIRY_URL = "expired-url";

	private static final String ATT_EXPIRED_SESSION_STRATEGY_REF = "expired-session-strategy-ref";

	private static final String ATT_SESSION_REGISTRY_ALIAS = "session-registry-alias";

	private static final String ATT_SESSION_REGISTRY_REF = "session-registry-ref";

	private static final String ATT_SERVLET_API_PROVISION = "servlet-api-provision";

	private static final String DEF_SERVLET_API_PROVISION = "true";

	private static final String ATT_JAAS_API_PROVISION = "jaas-api-provision";

	private static final String DEF_JAAS_API_PROVISION = "false";

	private final Element httpElt;

	private final ParserContext pc;

	private final SessionCreationPolicy sessionPolicy;

	private final List<Element> interceptUrls;

	private final MatcherType matcherType;

	private BeanDefinition cpf;

	private BeanDefinition securityContextPersistenceFilter;

	private BeanDefinition forceEagerSessionCreationFilter;

	private BeanMetadataElement holderStrategyRef;

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

	private BeanMetadataElement corsFilter;

	private BeanDefinition csrfFilter;

	private BeanDefinition disableUrlRewriteFilter;

	private BeanDefinition wellKnownChangePasswordRedirectFilter;

	private BeanMetadataElement csrfLogoutHandler;

	private BeanMetadataElement csrfAuthStrategy;

	private CsrfBeanDefinitionParser csrfParser;

	private BeanDefinition invalidSession;

	private boolean addAllAuth;

	HttpConfigurationBuilder(Element element, boolean addAllAuth, ParserContext pc, BeanReference portMapper,
			BeanReference portResolver, BeanReference authenticationManager, BeanMetadataElement observationRegistry) {
		this.httpElt = element;
		this.addAllAuth = addAllAuth;
		this.pc = pc;
		this.portMapper = portMapper;
		this.portResolver = portResolver;
		this.matcherType = MatcherType.fromElementOrMvc(element);
		this.interceptUrls = DomUtils.getChildElementsByTagName(element, Elements.INTERCEPT_URL);
		validateInterceptUrls(pc);
		String createSession = element.getAttribute(ATT_CREATE_SESSION);
		this.sessionPolicy = !StringUtils.hasText(createSession) ? SessionCreationPolicy.IF_REQUIRED
				: createPolicy(createSession);
		createSecurityContextHolderStrategy();
		createForceEagerSessionCreationFilter();
		createDisableEncodeUrlFilter();
		createCsrfFilter(observationRegistry);
		createSecurityPersistence();
		createSessionManagementFilters();
		createWebAsyncManagerFilter();
		createRequestCacheFilter();
		createServletApiFilter(authenticationManager);
		createJaasApiFilter();
		createChannelProcessingFilter();
		createFilterSecurity(authenticationManager);
		createAddHeadersFilter();
		createCorsFilter();
		createWellKnownChangePasswordRedirectFilter();
	}

	private void validateInterceptUrls(ParserContext pc) {
		for (Element element : this.interceptUrls) {
			if (StringUtils.hasText(element.getAttribute(HttpSecurityBeanDefinitionParser.ATT_FILTERS))) {
				String message = "The use of \"filters='none'\" is no longer supported. Please define a"
						+ " separate <http> element for the pattern you want to exclude and use the attribute"
						+ " \"security='none'\".";
				pc.getReaderContext().error(message, pc.extractSource(element));
			}
		}
	}

	private SessionCreationPolicy createPolicy(String createSession) {
		if ("ifRequired".equals(createSession)) {
			return SessionCreationPolicy.IF_REQUIRED;
		}
		if ("always".equals(createSession)) {
			return SessionCreationPolicy.ALWAYS;
		}
		if ("never".equals(createSession)) {
			return SessionCreationPolicy.NEVER;
		}
		if ("stateless".equals(createSession)) {
			return SessionCreationPolicy.STATELESS;
		}
		throw new IllegalStateException(
				"Cannot convert " + createSession + " to " + SessionCreationPolicy.class.getName());
	}

	@SuppressWarnings("rawtypes")
	void setLogoutHandlers(ManagedList logoutHandlers) {
		if (logoutHandlers != null) {
			if (this.concurrentSessionFilter != null) {
				this.concurrentSessionFilter.getPropertyValues().add("logoutHandlers", logoutHandlers);
			}
			if (this.servApiFilter != null) {
				this.servApiFilter.getPropertyValues().add("logoutHandlers", logoutHandlers);
			}
		}
	}

	void setEntryPoint(BeanMetadataElement entryPoint) {
		if (this.servApiFilter != null) {
			this.servApiFilter.getPropertyValues().add("authenticationEntryPoint", entryPoint);
		}
	}

	void setAccessDeniedHandler(BeanMetadataElement accessDeniedHandler) {
		if (this.csrfParser != null) {
			this.csrfParser.initAccessDeniedHandler(this.invalidSession, accessDeniedHandler);
		}
	}

	void setCsrfIgnoreRequestMatchers(List<BeanDefinition> requestMatchers) {
		if (this.csrfParser != null) {
			this.csrfParser.setIgnoreCsrfRequestMatchers(requestMatchers);
		}
	}

	// Needed to account for placeholders
	static String createPath(String path, boolean lowerCase) {
		return lowerCase ? path.toLowerCase(Locale.ENGLISH) : path;
	}

	BeanMetadataElement getSecurityContextHolderStrategyForAuthenticationFilters() {
		return this.holderStrategyRef;
	}

	BeanReference getSecurityContextRepositoryForAuthenticationFilters() {
		return (isExplicitSave()) ? this.contextRepoRef : null;
	}

	private void createSecurityPersistence() {
		createSecurityContextRepository();
		if (isExplicitSave()) {
			createSecurityContextHolderFilter();
		}
		else {
			createSecurityContextPersistenceFilter();
		}
	}

	private boolean isExplicitSave() {
		String explicitSaveAttr = this.httpElt.getAttribute(ATT_SECURITY_CONTEXT_EXPLICIT_SAVE);
		return !StringUtils.hasText(explicitSaveAttr) || Boolean.parseBoolean(explicitSaveAttr);
	}

	private void createForceEagerSessionCreationFilter() {
		if (this.sessionPolicy == SessionCreationPolicy.ALWAYS) {
			this.forceEagerSessionCreationFilter = new RootBeanDefinition(ForceEagerSessionCreationFilter.class);
		}
	}

	private void createSecurityContextPersistenceFilter() {
		BeanDefinitionBuilder scpf = BeanDefinitionBuilder.rootBeanDefinition(SecurityContextPersistenceFilter.class);
		switch (this.sessionPolicy) {
			case ALWAYS:
				scpf.addPropertyValue("forceEagerSessionCreation", Boolean.TRUE);
				break;
			case NEVER:
				scpf.addPropertyValue("forceEagerSessionCreation", Boolean.FALSE);
				break;
			default:
				scpf.addPropertyValue("forceEagerSessionCreation", Boolean.FALSE);
		}
		scpf.addPropertyValue("securityContextHolderStrategy", this.holderStrategyRef);
		scpf.addConstructorArgValue(this.contextRepoRef);

		this.securityContextPersistenceFilter = scpf.getBeanDefinition();
	}

	private void createSecurityContextHolderStrategy() {
		String holderStrategyRef = this.httpElt.getAttribute(ATT_SECURITY_CONTEXT_HOLDER_STRATEGY);
		if (StringUtils.hasText(holderStrategyRef)) {
			this.holderStrategyRef = new RuntimeBeanReference(holderStrategyRef);
			return;
		}
		this.holderStrategyRef = BeanDefinitionBuilder.rootBeanDefinition(SecurityContextHolderStrategyFactory.class)
			.getBeanDefinition();
	}

	private void createSecurityContextRepository() {
		String repoRef = this.httpElt.getAttribute(ATT_SECURITY_CONTEXT_REPOSITORY);
		if (!StringUtils.hasText(repoRef)) {
			BeanDefinitionBuilder contextRepo;
			if (this.sessionPolicy == SessionCreationPolicy.STATELESS) {
				contextRepo = BeanDefinitionBuilder.rootBeanDefinition(RequestAttributeSecurityContextRepository.class);
			}
			else {
				contextRepo = BeanDefinitionBuilder.rootBeanDefinition(HttpSessionSecurityContextRepository.class);
				switch (this.sessionPolicy) {
					case ALWAYS:
						contextRepo.addPropertyValue("allowSessionCreation", Boolean.TRUE);
						break;
					case NEVER:
						contextRepo.addPropertyValue("allowSessionCreation", Boolean.FALSE);
						break;
					default:
						contextRepo.addPropertyValue("allowSessionCreation", Boolean.TRUE);
				}
				if (isDisableUrlRewriting()) {
					contextRepo.addPropertyValue("disableUrlRewriting", Boolean.TRUE);
				}
			}
			contextRepo.addPropertyValue("securityContextHolderStrategy", this.holderStrategyRef);
			BeanDefinition repoBean = contextRepo.getBeanDefinition();
			repoRef = this.pc.getReaderContext().generateBeanName(repoBean);
			this.pc.registerBeanComponent(new BeanComponentDefinition(repoBean, repoRef));
		}

		this.contextRepoRef = new RuntimeBeanReference(repoRef);
	}

	private boolean isDisableUrlRewriting() {
		String disableUrlRewriting = this.httpElt.getAttribute(ATT_DISABLE_URL_REWRITING);
		return !"false".equals(disableUrlRewriting);
	}

	private void createSecurityContextHolderFilter() {
		BeanDefinitionBuilder filter = BeanDefinitionBuilder.rootBeanDefinition(SecurityContextHolderFilter.class);
		filter.addPropertyValue("securityContextHolderStrategy", this.holderStrategyRef);
		filter.addConstructorArgValue(this.contextRepoRef);
		this.securityContextPersistenceFilter = filter.getBeanDefinition();
	}

	private void createSessionManagementFilters() {
		Element sessionMgmtElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.SESSION_MANAGEMENT);
		Element sessionCtrlElt = null;
		String sessionFixationAttribute = null;
		String invalidSessionUrl = null;
		String invalidSessionStrategyRef = null;
		String sessionAuthStratRef = null;
		String errorUrl = null;
		boolean sessionControlEnabled = false;
		if (sessionMgmtElt != null) {
			if (this.sessionPolicy == SessionCreationPolicy.STATELESS) {
				this.pc.getReaderContext()
					.error(Elements.SESSION_MANAGEMENT + "  cannot be used" + " in combination with "
							+ ATT_CREATE_SESSION + "='" + SessionCreationPolicy.STATELESS + "'",
							this.pc.extractSource(sessionMgmtElt));
			}
			sessionFixationAttribute = sessionMgmtElt.getAttribute(ATT_SESSION_FIXATION_PROTECTION);
			invalidSessionUrl = sessionMgmtElt.getAttribute(ATT_INVALID_SESSION_URL);
			invalidSessionStrategyRef = sessionMgmtElt.getAttribute(ATT_INVALID_SESSION_STRATEGY_REF);
			sessionAuthStratRef = sessionMgmtElt.getAttribute(ATT_SESSION_AUTH_STRATEGY_REF);
			errorUrl = sessionMgmtElt.getAttribute(ATT_SESSION_AUTH_ERROR_URL);
			sessionCtrlElt = DomUtils.getChildElementByTagName(sessionMgmtElt, Elements.CONCURRENT_SESSIONS);
			sessionControlEnabled = sessionCtrlElt != null;
			if (StringUtils.hasText(invalidSessionUrl) && StringUtils.hasText(invalidSessionStrategyRef)) {
				this.pc.getReaderContext()
					.error(ATT_INVALID_SESSION_URL + " attribute cannot be used in combination with" + " the "
							+ ATT_INVALID_SESSION_STRATEGY_REF + " attribute.", sessionMgmtElt);
			}
			if (sessionControlEnabled) {
				if (StringUtils.hasText(sessionAuthStratRef)) {
					this.pc.getReaderContext()
						.error(ATT_SESSION_AUTH_STRATEGY_REF + " attribute cannot be used" + " in combination with <"
								+ Elements.CONCURRENT_SESSIONS + ">", this.pc.extractSource(sessionCtrlElt));
				}
				createConcurrencyControlFilterAndSessionRegistry(sessionCtrlElt);
			}
		}

		if (!StringUtils.hasText(sessionFixationAttribute)) {
			sessionFixationAttribute = OPT_CHANGE_SESSION_ID;
		}
		else if (StringUtils.hasText(sessionAuthStratRef)) {
			this.pc.getReaderContext()
				.error(ATT_SESSION_FIXATION_PROTECTION + " attribute cannot be used" + " in combination with "
						+ ATT_SESSION_AUTH_STRATEGY_REF, this.pc.extractSource(sessionMgmtElt));
		}

		if (this.sessionPolicy == SessionCreationPolicy.STATELESS) {
			// SEC-1424: do nothing
			return;
		}
		boolean sessionFixationProtectionRequired = !sessionFixationAttribute
			.equals(OPT_SESSION_FIXATION_NO_PROTECTION);
		ManagedList<BeanMetadataElement> delegateSessionStrategies = new ManagedList<>();
		BeanDefinitionBuilder concurrentSessionStrategy;
		BeanDefinitionBuilder sessionFixationStrategy = null;
		BeanDefinitionBuilder registerSessionStrategy;
		if (this.csrfAuthStrategy != null) {
			delegateSessionStrategies.add(this.csrfAuthStrategy);
		}
		if (sessionControlEnabled) {
			Assert.state(this.sessionRegistryRef != null, "No sessionRegistryRef found");
			concurrentSessionStrategy = BeanDefinitionBuilder
				.rootBeanDefinition(ConcurrentSessionControlAuthenticationStrategy.class);
			concurrentSessionStrategy.addConstructorArgValue(this.sessionRegistryRef);
			String maxSessions = this.pc.getReaderContext()
				.getEnvironment()
				.resolvePlaceholders(sessionCtrlElt.getAttribute("max-sessions"));
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
			if (useChangeSessionId) {
				sessionFixationStrategy = BeanDefinitionBuilder
					.rootBeanDefinition(ChangeSessionIdAuthenticationStrategy.class);
			}
			else {
				sessionFixationStrategy = BeanDefinitionBuilder
					.rootBeanDefinition(SessionFixationProtectionStrategy.class);
			}
			delegateSessionStrategies.add(sessionFixationStrategy.getBeanDefinition());
		}
		if (StringUtils.hasText(sessionAuthStratRef)) {
			delegateSessionStrategies.add(new RuntimeBeanReference(sessionAuthStratRef));
		}
		if (sessionControlEnabled) {
			registerSessionStrategy = BeanDefinitionBuilder
				.rootBeanDefinition(RegisterSessionAuthenticationStrategy.class);
			registerSessionStrategy.addConstructorArgValue(this.sessionRegistryRef);
			delegateSessionStrategies.add(registerSessionStrategy.getBeanDefinition());
		}
		if (delegateSessionStrategies.isEmpty()) {
			this.sfpf = null;
			return;
		}
		BeanDefinitionBuilder sessionMgmtFilter = BeanDefinitionBuilder
			.rootBeanDefinition(SessionManagementFilter.class);
		RootBeanDefinition failureHandler = new RootBeanDefinition(SimpleUrlAuthenticationFailureHandler.class);
		if (StringUtils.hasText(errorUrl)) {
			failureHandler.getPropertyValues().addPropertyValue("defaultFailureUrl", errorUrl);
		}
		sessionMgmtFilter.addPropertyValue("securityContextHolderStrategy", this.holderStrategyRef);
		sessionMgmtFilter.addPropertyValue("authenticationFailureHandler", failureHandler);
		sessionMgmtFilter.addConstructorArgValue(this.contextRepoRef);
		if (!StringUtils.hasText(sessionAuthStratRef) && sessionFixationStrategy != null && !useChangeSessionId) {
			if (sessionFixationProtectionRequired) {
				sessionFixationStrategy.addPropertyValue("migrateSessionAttributes",
						sessionFixationAttribute.equals(OPT_SESSION_FIXATION_MIGRATE_SESSION));
			}
		}
		if (!delegateSessionStrategies.isEmpty()) {
			BeanDefinitionBuilder sessionStrategy = BeanDefinitionBuilder
				.rootBeanDefinition(CompositeSessionAuthenticationStrategy.class);
			BeanDefinition strategyBean = sessionStrategy.getBeanDefinition();
			sessionStrategy.addConstructorArgValue(delegateSessionStrategies);
			sessionAuthStratRef = this.pc.getReaderContext().generateBeanName(strategyBean);
			this.pc.registerBeanComponent(new BeanComponentDefinition(strategyBean, sessionAuthStratRef));
		}
		if (StringUtils.hasText(invalidSessionUrl)) {
			BeanDefinitionBuilder invalidSessionBldr = BeanDefinitionBuilder
				.rootBeanDefinition(SimpleRedirectInvalidSessionStrategy.class);
			invalidSessionBldr.addConstructorArgValue(invalidSessionUrl);
			this.invalidSession = invalidSessionBldr.getBeanDefinition();
			sessionMgmtFilter.addPropertyValue("invalidSessionStrategy", this.invalidSession);
		}
		else if (StringUtils.hasText(invalidSessionStrategyRef)) {
			sessionMgmtFilter.addPropertyReference("invalidSessionStrategy", invalidSessionStrategyRef);
		}
		sessionMgmtFilter.addConstructorArgReference(sessionAuthStratRef);
		boolean registerSessionMgmtFilter = (sessionMgmtElt != null
				&& "false".equals(sessionMgmtElt.getAttribute(ATT_AUTHENTICATION_STRATEGY_EXPLICIT_INVOCATION)));
		if (registerSessionMgmtFilter || StringUtils.hasText(errorUrl) || StringUtils.hasText(invalidSessionUrl)
				|| StringUtils.hasText(invalidSessionStrategyRef)) {
			this.sfpf = (RootBeanDefinition) sessionMgmtFilter.getBeanDefinition();
		}
		this.sessionStrategyRef = new RuntimeBeanReference(sessionAuthStratRef);
	}

	private void createConcurrencyControlFilterAndSessionRegistry(Element element) {
		CompositeComponentDefinition compositeDef = new CompositeComponentDefinition(element.getTagName(),
				this.pc.extractSource(element));
		this.pc.pushContainingComponent(compositeDef);
		BeanDefinitionRegistry beanRegistry = this.pc.getRegistry();
		String sessionRegistryId = element.getAttribute(ATT_SESSION_REGISTRY_REF);
		if (!StringUtils.hasText(sessionRegistryId)) {
			// Register an internal SessionRegistryImpl if no external reference supplied.
			RootBeanDefinition sessionRegistry = new RootBeanDefinition(SessionRegistryImpl.class);
			sessionRegistryId = this.pc.getReaderContext().registerWithGeneratedName(sessionRegistry);
			this.pc.registerComponent(new BeanComponentDefinition(sessionRegistry, sessionRegistryId));
		}
		String registryAlias = element.getAttribute(ATT_SESSION_REGISTRY_ALIAS);
		if (StringUtils.hasText(registryAlias)) {
			beanRegistry.registerAlias(sessionRegistryId, registryAlias);
		}
		BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder.rootBeanDefinition(ConcurrentSessionFilter.class);
		filterBuilder.addConstructorArgReference(sessionRegistryId);
		Object source = this.pc.extractSource(element);
		filterBuilder.getRawBeanDefinition().setSource(source);
		filterBuilder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
		String expiryUrl = element.getAttribute(ATT_EXPIRY_URL);
		String expiredSessionStrategyRef = element.getAttribute(ATT_EXPIRED_SESSION_STRATEGY_REF);
		if (StringUtils.hasText(expiryUrl) && StringUtils.hasText(expiredSessionStrategyRef)) {
			this.pc.getReaderContext()
				.error("Cannot use 'expired-url' attribute and 'expired-session-strategy-ref'" + " attribute together.",
						source);
		}
		if (StringUtils.hasText(expiryUrl)) {
			BeanDefinitionBuilder expiredSessionBldr = BeanDefinitionBuilder
				.rootBeanDefinition(SimpleRedirectSessionInformationExpiredStrategy.class);
			expiredSessionBldr.addConstructorArgValue(expiryUrl);
			filterBuilder.addConstructorArgValue(expiredSessionBldr.getBeanDefinition());
		}
		else if (StringUtils.hasText(expiredSessionStrategyRef)) {
			filterBuilder.addConstructorArgReference(expiredSessionStrategyRef);
		}
		this.pc.popAndRegisterContainingComponent();
		this.concurrentSessionFilter = filterBuilder.getBeanDefinition();
		this.sessionRegistryRef = new RuntimeBeanReference(sessionRegistryId);
	}

	private void createWebAsyncManagerFilter() {
		boolean asyncSupported = ClassUtils.hasMethod(ServletRequest.class, "startAsync");
		if (asyncSupported) {
			this.webAsyncManagerFilter = new RootBeanDefinition(WebAsyncManagerIntegrationFilter.class);
			this.webAsyncManagerFilter.getPropertyValues().add("securityContextHolderStrategy", this.holderStrategyRef);
		}
	}

	// Adds the servlet-api integration filter if required
	private void createServletApiFilter(BeanReference authenticationManager) {
		String provideServletApi = this.httpElt.getAttribute(ATT_SERVLET_API_PROVISION);
		if (!StringUtils.hasText(provideServletApi)) {
			provideServletApi = DEF_SERVLET_API_PROVISION;
		}
		if ("true".equals(provideServletApi)) {
			this.servApiFilter = GrantedAuthorityDefaultsParserUtils.registerWithDefaultRolePrefix(this.pc,
					SecurityContextHolderAwareRequestFilterBeanFactory.class);
			this.servApiFilter.getPropertyValues().add("authenticationManager", authenticationManager);
			this.servApiFilter.getPropertyValues().add("securityContextHolderStrategy", this.holderStrategyRef);
		}
	}

	// Adds the jaas-api integration filter if required
	private void createJaasApiFilter() {
		String provideJaasApi = this.httpElt.getAttribute(ATT_JAAS_API_PROVISION);
		if (!StringUtils.hasText(provideJaasApi)) {
			provideJaasApi = DEF_JAAS_API_PROVISION;
		}
		if ("true".equals(provideJaasApi)) {
			this.jaasApiFilter = BeanDefinitionBuilder.rootBeanDefinition(JaasApiIntegrationFilter.class)
				.addPropertyValue("securityContextHolderStrategy", this.holderStrategyRef)
				.getBeanDefinition();
		}
	}

	private void createChannelProcessingFilter() {
		ManagedMap<BeanMetadataElement, BeanDefinition> channelRequestMap = parseInterceptUrlsForChannelSecurity();
		if (channelRequestMap.isEmpty()) {
			return;
		}
		RootBeanDefinition channelFilter = new RootBeanDefinition(ChannelProcessingFilter.class);
		BeanDefinitionBuilder metadataSourceBldr = BeanDefinitionBuilder
			.rootBeanDefinition(DefaultFilterInvocationSecurityMetadataSource.class);
		metadataSourceBldr.addConstructorArgValue(channelRequestMap);
		channelFilter.getPropertyValues()
			.addPropertyValue("securityMetadataSource", metadataSourceBldr.getBeanDefinition());
		RootBeanDefinition channelDecisionManager = new RootBeanDefinition(ChannelDecisionManagerImpl.class);
		ManagedList<RootBeanDefinition> channelProcessors = new ManagedList<>(3);
		RootBeanDefinition secureChannelProcessor = new RootBeanDefinition(SecureChannelProcessor.class);
		RootBeanDefinition retryWithHttp = new RootBeanDefinition(RetryWithHttpEntryPoint.class);
		RootBeanDefinition retryWithHttps = new RootBeanDefinition(RetryWithHttpsEntryPoint.class);
		retryWithHttp.getPropertyValues().addPropertyValue("portMapper", this.portMapper);
		retryWithHttp.getPropertyValues().addPropertyValue("portResolver", this.portResolver);
		retryWithHttps.getPropertyValues().addPropertyValue("portMapper", this.portMapper);
		retryWithHttps.getPropertyValues().addPropertyValue("portResolver", this.portResolver);
		secureChannelProcessor.getPropertyValues().addPropertyValue("entryPoint", retryWithHttps);
		RootBeanDefinition inSecureChannelProcessor = new RootBeanDefinition(InsecureChannelProcessor.class);
		inSecureChannelProcessor.getPropertyValues().addPropertyValue("entryPoint", retryWithHttp);
		channelProcessors.add(secureChannelProcessor);
		channelProcessors.add(inSecureChannelProcessor);
		channelDecisionManager.getPropertyValues().addPropertyValue("channelProcessors", channelProcessors);
		String id = this.pc.getReaderContext().registerWithGeneratedName(channelDecisionManager);
		channelFilter.getPropertyValues().addPropertyValue("channelDecisionManager", new RuntimeBeanReference(id));
		this.cpf = channelFilter;
	}

	/**
	 * Parses the intercept-url elements to obtain the map used by channel security. This
	 * will be empty unless the <tt>requires-channel</tt> attribute has been used on a URL
	 * path.
	 */
	private ManagedMap<BeanMetadataElement, BeanDefinition> parseInterceptUrlsForChannelSecurity() {
		ManagedMap<BeanMetadataElement, BeanDefinition> channelRequestMap = new ManagedMap<>();
		for (Element urlElt : this.interceptUrls) {
			String path = urlElt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_PATH_PATTERN);
			String method = urlElt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_HTTP_METHOD);
			String matcherRef = urlElt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_REQUEST_MATCHER_REF);
			boolean hasMatcherRef = StringUtils.hasText(matcherRef);
			if (!hasMatcherRef && !StringUtils.hasText(path)) {
				this.pc.getReaderContext().error("pattern attribute cannot be empty or null", urlElt);
			}
			String requiredChannel = urlElt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_REQUIRES_CHANNEL);
			if (StringUtils.hasText(requiredChannel)) {
				BeanMetadataElement matcher = hasMatcherRef ? new RuntimeBeanReference(matcherRef)
						: this.matcherType.createMatcher(this.pc, path, method);
				RootBeanDefinition channelAttributes = new RootBeanDefinition(ChannelAttributeFactory.class);
				channelAttributes.getConstructorArgumentValues().addGenericArgumentValue(requiredChannel);
				channelAttributes.setFactoryMethodName("createChannelAttributes");
				channelRequestMap.put(matcher, channelAttributes);
			}
		}
		return channelRequestMap;
	}

	private void createRequestCacheFilter() {
		Element requestCacheElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.REQUEST_CACHE);
		if (requestCacheElt != null) {
			this.requestCache = new RuntimeBeanReference(requestCacheElt.getAttribute(ATT_REF));
		}
		else {
			BeanDefinitionBuilder requestCacheBldr;
			if (this.sessionPolicy == SessionCreationPolicy.STATELESS) {
				requestCacheBldr = BeanDefinitionBuilder.rootBeanDefinition(NullRequestCache.class);
			}
			else {
				requestCacheBldr = BeanDefinitionBuilder.rootBeanDefinition(HttpSessionRequestCache.class);
				requestCacheBldr.addPropertyValue("createSessionAllowed",
						this.sessionPolicy == SessionCreationPolicy.IF_REQUIRED);
				requestCacheBldr.addPropertyValue("portResolver", this.portResolver);
				if (this.csrfFilter != null) {
					BeanDefinitionBuilder requestCacheMatcherBldr = BeanDefinitionBuilder
						.rootBeanDefinition(AntPathRequestMatcher.class);
					requestCacheMatcherBldr.addConstructorArgValue("/**");
					requestCacheMatcherBldr.addConstructorArgValue("GET");
					requestCacheBldr.addPropertyValue("requestMatcher", requestCacheMatcherBldr.getBeanDefinition());
				}
			}
			BeanDefinition bean = requestCacheBldr.getBeanDefinition();
			String id = this.pc.getReaderContext().generateBeanName(bean);
			this.pc.registerBeanComponent(new BeanComponentDefinition(bean, id));
			this.requestCache = new RuntimeBeanReference(id);
		}
		this.requestCacheAwareFilter = new RootBeanDefinition(RequestCacheAwareFilter.class);
		this.requestCacheAwareFilter.getConstructorArgumentValues().addGenericArgumentValue(this.requestCache);
	}

	private void createFilterSecurity(BeanReference authManager) {
		if (StringUtils.hasText(this.httpElt.getAttribute(ATT_AUTHORIZATION_MGR))) {
			createAuthorizationFilter();
			return;
		}
		boolean useAuthorizationManager = true;
		if (StringUtils.hasText(this.httpElt.getAttribute(ATT_USE_AUTHORIZATION_MGR))) {
			useAuthorizationManager = Boolean.parseBoolean(this.httpElt.getAttribute(ATT_USE_AUTHORIZATION_MGR));
		}
		if (useAuthorizationManager) {
			createAuthorizationFilter();
			return;
		}
		createFilterSecurityInterceptor(authManager);
	}

	private void createAuthorizationFilter() {
		AuthorizationFilterParser authorizationFilterParser = new AuthorizationFilterParser(this.holderStrategyRef);
		BeanDefinition fsiBean = authorizationFilterParser.parse(this.httpElt, this.pc);
		String fsiId = this.pc.getReaderContext().generateBeanName(fsiBean);
		this.pc.registerBeanComponent(new BeanComponentDefinition(fsiBean, fsiId));
		// Create and register a AuthorizationManagerWebInvocationPrivilegeEvaluator for
		// use with
		// taglibs etc.
		BeanDefinitionBuilder wipeBldr = BeanDefinitionBuilder
			.rootBeanDefinition(AuthorizationManagerWebInvocationPrivilegeEvaluator.class)
			.addConstructorArgReference(authorizationFilterParser.getAuthorizationManagerRef());
		if (mvcPresent) {
			wipeBldr.addPropertyValue("requestTransformer",
					new RootBeanDefinition(HandlerMappingIntrospectorRequestTransformerFactoryBean.class));
		}
		BeanDefinition wipe = wipeBldr.getBeanDefinition();
		this.pc.registerBeanComponent(
				new BeanComponentDefinition(wipe, this.pc.getReaderContext().generateBeanName(wipe)));
		this.fsi = new RuntimeBeanReference(fsiId);
	}

	private void createFilterSecurityInterceptor(BeanReference authManager) {
		boolean useExpressions = FilterInvocationSecurityMetadataSourceParser.isUseExpressions(this.httpElt);
		RootBeanDefinition securityMds = FilterInvocationSecurityMetadataSourceParser
			.createSecurityMetadataSource(this.interceptUrls, this.addAllAuth, this.httpElt, this.pc);
		RootBeanDefinition accessDecisionMgr;
		ManagedList<BeanDefinition> voters = new ManagedList<>(2);
		if (useExpressions) {
			BeanDefinitionBuilder expressionVoter = BeanDefinitionBuilder.rootBeanDefinition(WebExpressionVoter.class);
			// Read the expression handler from the FISMS
			RuntimeBeanReference expressionHandler = (RuntimeBeanReference) securityMds.getConstructorArgumentValues()
				.getArgumentValue(1, RuntimeBeanReference.class)
				.getValue();
			expressionVoter.addPropertyValue("expressionHandler", expressionHandler);
			voters.add(expressionVoter.getBeanDefinition());
		}
		else {
			voters.add(GrantedAuthorityDefaultsParserUtils.registerWithDefaultRolePrefix(this.pc,
					RoleVoterBeanFactory.class));
			voters.add(new RootBeanDefinition(AuthenticatedVoter.class));
		}
		accessDecisionMgr = new RootBeanDefinition(AffirmativeBased.class);
		accessDecisionMgr.getConstructorArgumentValues().addGenericArgumentValue(voters);
		accessDecisionMgr.setSource(this.pc.extractSource(this.httpElt));
		// Set up the access manager reference for http
		String accessManagerId = this.httpElt.getAttribute(ATT_ACCESS_MGR);
		if (!StringUtils.hasText(accessManagerId)) {
			accessManagerId = this.pc.getReaderContext().generateBeanName(accessDecisionMgr);
			this.pc.registerBeanComponent(new BeanComponentDefinition(accessDecisionMgr, accessManagerId));
		}
		BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(FilterSecurityInterceptor.class);
		builder.addPropertyReference("accessDecisionManager", accessManagerId);
		builder.addPropertyValue("authenticationManager", authManager);
		if ("true".equals(this.httpElt.getAttribute(ATT_ONCE_PER_REQUEST))) {
			builder.addPropertyValue("observeOncePerRequest", Boolean.TRUE);
		}
		builder.addPropertyValue("securityMetadataSource", securityMds);
		builder.addPropertyValue("securityContextHolderStrategy", this.holderStrategyRef);
		BeanDefinition fsiBean = builder.getBeanDefinition();
		String fsiId = this.pc.getReaderContext().generateBeanName(fsiBean);
		this.pc.registerBeanComponent(new BeanComponentDefinition(fsiBean, fsiId));
		// Create and register a DefaultWebInvocationPrivilegeEvaluator for use with
		// taglibs etc.
		BeanDefinition wipe = new RootBeanDefinition(DefaultWebInvocationPrivilegeEvaluator.class);
		wipe.getConstructorArgumentValues().addGenericArgumentValue(new RuntimeBeanReference(fsiId));
		this.pc.registerBeanComponent(
				new BeanComponentDefinition(wipe, this.pc.getReaderContext().generateBeanName(wipe)));
		this.fsi = new RuntimeBeanReference(fsiId);
	}

	private void createAddHeadersFilter() {
		Element elmt = DomUtils.getChildElementByTagName(this.httpElt, Elements.HEADERS);
		this.addHeadersFilter = new HeadersBeanDefinitionParser().parse(elmt, this.pc);
	}

	private void createCorsFilter() {
		Element elmt = DomUtils.getChildElementByTagName(this.httpElt, Elements.CORS);
		this.corsFilter = new CorsBeanDefinitionParser().parse(elmt, this.pc);

	}

	private void createDisableEncodeUrlFilter() {
		if (isDisableUrlRewriting()) {
			this.disableUrlRewriteFilter = new RootBeanDefinition(DisableEncodeUrlFilter.class);
		}
	}

	private void createCsrfFilter(BeanMetadataElement observationRegistry) {
		Element elmt = DomUtils.getChildElementByTagName(this.httpElt, Elements.CSRF);
		this.csrfParser = new CsrfBeanDefinitionParser();
		this.csrfParser.setObservationRegistry(observationRegistry);
		this.csrfFilter = this.csrfParser.parse(elmt, this.pc);
		if (this.csrfFilter == null) {
			this.csrfParser = null;
			return;
		}
		this.csrfAuthStrategy = this.csrfParser.getCsrfAuthenticationStrategy();
		this.csrfLogoutHandler = this.csrfParser.getCsrfLogoutHandler();
	}

	private void createWellKnownChangePasswordRedirectFilter() {
		Element element = DomUtils.getChildElementByTagName(this.httpElt, Elements.PASSWORD_MANAGEMENT);
		if (element == null) {
			return;
		}
		WellKnownChangePasswordBeanDefinitionParser parser = new WellKnownChangePasswordBeanDefinitionParser();
		this.wellKnownChangePasswordRedirectFilter = parser.parse(element, this.pc);
	}

	BeanMetadataElement getCsrfLogoutHandler() {
		return this.csrfLogoutHandler;
	}

	BeanReference getSessionStrategy() {
		return this.sessionStrategyRef;
	}

	SessionCreationPolicy getSessionCreationPolicy() {
		return this.sessionPolicy;
	}

	BeanReference getRequestCache() {
		return this.requestCache;
	}

	List<OrderDecorator> getFilters() {
		List<OrderDecorator> filters = new ArrayList<>();
		if (this.forceEagerSessionCreationFilter != null) {
			filters.add(new OrderDecorator(this.forceEagerSessionCreationFilter,
					SecurityFilters.FORCE_EAGER_SESSION_FILTER));
		}
		if (this.disableUrlRewriteFilter != null) {
			filters.add(new OrderDecorator(this.disableUrlRewriteFilter, SecurityFilters.DISABLE_ENCODE_URL_FILTER));
		}
		if (this.cpf != null) {
			filters.add(new OrderDecorator(this.cpf, SecurityFilters.CHANNEL_FILTER));
		}
		if (this.concurrentSessionFilter != null) {
			filters.add(new OrderDecorator(this.concurrentSessionFilter, SecurityFilters.CONCURRENT_SESSION_FILTER));
		}
		if (this.webAsyncManagerFilter != null) {
			filters.add(new OrderDecorator(this.webAsyncManagerFilter, SecurityFilters.WEB_ASYNC_MANAGER_FILTER));
		}
		filters.add(new OrderDecorator(this.securityContextPersistenceFilter, SecurityFilters.SECURITY_CONTEXT_FILTER));
		if (this.servApiFilter != null) {
			filters.add(new OrderDecorator(this.servApiFilter, SecurityFilters.SERVLET_API_SUPPORT_FILTER));
		}
		if (this.jaasApiFilter != null) {
			filters.add(new OrderDecorator(this.jaasApiFilter, SecurityFilters.JAAS_API_SUPPORT_FILTER));
		}
		if (this.sfpf != null) {
			filters.add(new OrderDecorator(this.sfpf, SecurityFilters.SESSION_MANAGEMENT_FILTER));
		}
		filters.add(new OrderDecorator(this.fsi, SecurityFilters.FILTER_SECURITY_INTERCEPTOR));
		if (this.sessionPolicy != SessionCreationPolicy.STATELESS) {
			filters.add(new OrderDecorator(this.requestCacheAwareFilter, SecurityFilters.REQUEST_CACHE_FILTER));
		}
		if (this.corsFilter != null) {
			filters.add(new OrderDecorator(this.corsFilter, SecurityFilters.CORS_FILTER));
		}
		if (this.addHeadersFilter != null) {
			filters.add(new OrderDecorator(this.addHeadersFilter, SecurityFilters.HEADERS_FILTER));
		}
		if (this.csrfFilter != null) {
			filters.add(new OrderDecorator(this.csrfFilter, SecurityFilters.CSRF_FILTER));
		}
		if (this.wellKnownChangePasswordRedirectFilter != null) {
			filters.add(new OrderDecorator(this.wellKnownChangePasswordRedirectFilter,
					SecurityFilters.WELL_KNOWN_CHANGE_PASSWORD_REDIRECT_FILTER));
		}
		return filters;
	}

	private static BeanMetadataElement getObservationRegistry(Element httpElmt) {
		String holderStrategyRef = httpElmt.getAttribute(ATT_OBSERVATION_REGISTRY_REF);
		if (StringUtils.hasText(holderStrategyRef)) {
			return new RuntimeBeanReference(holderStrategyRef);
		}
		return BeanDefinitionBuilder.rootBeanDefinition(ObservationRegistryFactory.class).getBeanDefinition();
	}

	static class HandlerMappingIntrospectorRequestTransformerFactoryBean
			implements FactoryBean<AuthorizationManagerWebInvocationPrivilegeEvaluator.HttpServletRequestTransformer>,
			ApplicationContextAware {

		private ApplicationContext applicationContext;

		@Override
		public AuthorizationManagerWebInvocationPrivilegeEvaluator.HttpServletRequestTransformer getObject()
				throws Exception {
			HandlerMappingIntrospector hmi = this.applicationContext.getBeanProvider(HandlerMappingIntrospector.class)
				.getIfAvailable();
			return (hmi != null) ? new HandlerMappingIntrospectorRequestTransformer(hmi)
					: AuthorizationManagerWebInvocationPrivilegeEvaluator.HttpServletRequestTransformer.IDENTITY;
		}

		@Override
		public Class<?> getObjectType() {
			return AuthorizationManagerWebInvocationPrivilegeEvaluator.HttpServletRequestTransformer.class;
		}

		@Override
		public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
			this.applicationContext = applicationContext;
		}

	}

	static class RoleVoterBeanFactory extends AbstractGrantedAuthorityDefaultsBeanFactory {

		private RoleVoter voter = new RoleVoter();

		@Override
		public RoleVoter getBean() {
			this.voter.setRolePrefix(this.rolePrefix);
			return this.voter;
		}

	}

	static class SecurityContextHolderAwareRequestFilterBeanFactory
			extends GrantedAuthorityDefaultsParserUtils.AbstractGrantedAuthorityDefaultsBeanFactory {

		private SecurityContextHolderAwareRequestFilter filter = new SecurityContextHolderAwareRequestFilter();

		private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

		@Override
		public SecurityContextHolderAwareRequestFilter getBean() {
			this.filter.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
			this.filter.setRolePrefix(this.rolePrefix);
			return this.filter;
		}

		void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
			this.securityContextHolderStrategy = securityContextHolderStrategy;
		}

	}

	static class SecurityContextHolderStrategyFactory implements FactoryBean<SecurityContextHolderStrategy> {

		@Override
		public SecurityContextHolderStrategy getObject() throws Exception {
			return SecurityContextHolder.getContextHolderStrategy();
		}

		@Override
		public Class<?> getObjectType() {
			return SecurityContextHolderStrategy.class;
		}

	}

	static class ObservationRegistryFactory implements FactoryBean<ObservationRegistry> {

		@Override
		public ObservationRegistry getObject() throws Exception {
			return ObservationRegistry.NOOP;
		}

		@Override
		public Class<?> getObjectType() {
			return ObservationRegistry.class;
		}

	}

}
