/*
 * Copyright 2002-2022 the original author or authors.
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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.Elements;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleMappableAttributesRetriever;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.RequestMatcherDelegatingAccessDeniedHandler;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;
import org.springframework.security.web.authentication.preauth.j2ee.J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

/**
 * Handles creation of authentication mechanism filters and related beans for &lt;http&gt;
 * parsing.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.0
 */
final class AuthenticationConfigBuilder {

	private final Log logger = LogFactory.getLog(getClass());

	private static final String ATT_REALM = "realm";

	private static final String DEF_REALM = "Realm";

	static final String AUTHENTICATION_PROCESSING_FILTER_CLASS = "org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter";

	static final String ATT_AUTH_DETAILS_SOURCE_REF = "authentication-details-source-ref";

	private static final String ATT_AUTO_CONFIG = "auto-config";

	private static final String ATT_ACCESS_DENIED_ERROR_PAGE = "error-page";

	private static final String ATT_ENTRY_POINT_REF = "entry-point-ref";

	private static final String ATT_USER_SERVICE_REF = "user-service-ref";

	private static final String ATT_KEY = "key";

	private static final String ATT_MAPPABLE_ROLES = "mappable-roles";

	private final Element httpElt;

	private final ParserContext pc;

	private final boolean autoConfig;

	private final boolean allowSessionCreation;

	private RootBeanDefinition anonymousFilter;

	private BeanReference anonymousProviderRef;

	private BeanDefinition rememberMeFilter;

	private String rememberMeServicesId;

	private BeanReference rememberMeProviderRef;

	private BeanDefinition basicFilter;

	private RuntimeBeanReference basicEntryPoint;

	private BeanDefinition formEntryPoint;

	private String formFilterId = null;

	private BeanDefinition x509Filter;

	private BeanReference x509ProviderRef;

	private BeanDefinition jeeFilter;

	private BeanReference jeeProviderRef;

	private RootBeanDefinition preAuthEntryPoint;

	private BeanMetadataElement mainEntryPoint;

	private BeanMetadataElement accessDeniedHandler;

	private BeanDefinition bearerTokenAuthenticationFilter;

	private BeanDefinition logoutFilter;

	@SuppressWarnings("rawtypes")
	private ManagedList logoutHandlers;

	private BeanMetadataElement logoutSuccessHandler;

	private BeanDefinition loginPageGenerationFilter;

	private BeanDefinition logoutPageGenerationFilter;

	private BeanDefinition etf;

	private final BeanReference requestCache;

	private final BeanReference portMapper;

	private final BeanReference portResolver;

	private final BeanMetadataElement csrfLogoutHandler;

	private String loginProcessingUrl;

	private String formLoginPage;

	private boolean oauth2LoginEnabled;

	private boolean defaultAuthorizedClientRepositoryRegistered;

	private String oauth2LoginFilterId;

	private BeanDefinition oauth2AuthorizationRequestRedirectFilter;

	private BeanDefinition oauth2LoginEntryPoint;

	private BeanReference oauth2LoginAuthenticationProviderRef;

	private BeanReference oauth2LoginOidcAuthenticationProviderRef;

	private BeanDefinition oauth2LoginLinks;

	private BeanDefinition saml2AuthenticationUrlToProviderName;

	private BeanDefinition saml2AuthorizationRequestFilter;

	private String saml2AuthenticationFilterId;

	private String saml2AuthenticationRequestFilterId;

	private String saml2LogoutFilterId;

	private String saml2LogoutRequestFilterId;

	private String saml2LogoutResponseFilterId;

	private boolean oauth2ClientEnabled;

	private BeanDefinition authorizationRequestRedirectFilter;

	private BeanDefinition authorizationCodeGrantFilter;

	private BeanReference authorizationCodeAuthenticationProviderRef;

	private final List<BeanReference> authenticationProviders = new ManagedList<>();

	private final Map<BeanDefinition, BeanMetadataElement> defaultDeniedHandlerMappings = new ManagedMap<>();

	private final Map<BeanDefinition, BeanMetadataElement> defaultEntryPointMappings = new ManagedMap<>();

	private final List<BeanDefinition> csrfIgnoreRequestMatchers = new ManagedList<>();

	AuthenticationConfigBuilder(Element element, boolean forceAutoConfig, ParserContext pc,
			SessionCreationPolicy sessionPolicy, BeanReference requestCache, BeanReference authenticationManager,
			BeanMetadataElement authenticationFilterSecurityContextHolderStrategyRef,
			BeanReference authenticationFilterSecurityContextRepositoryRef, BeanReference sessionStrategy,
			BeanReference portMapper, BeanReference portResolver, BeanMetadataElement csrfLogoutHandler) {
		this.httpElt = element;
		this.pc = pc;
		this.requestCache = requestCache;
		this.autoConfig = forceAutoConfig | "true".equals(element.getAttribute(ATT_AUTO_CONFIG));
		this.allowSessionCreation = sessionPolicy != SessionCreationPolicy.NEVER
				&& sessionPolicy != SessionCreationPolicy.STATELESS;
		this.portMapper = portMapper;
		this.portResolver = portResolver;
		this.csrfLogoutHandler = csrfLogoutHandler;
		createAnonymousFilter(authenticationFilterSecurityContextHolderStrategyRef);
		createRememberMeFilter(authenticationManager, authenticationFilterSecurityContextHolderStrategyRef);
		createBasicFilter(authenticationManager, authenticationFilterSecurityContextHolderStrategyRef);
		createBearerTokenAuthenticationFilter(authenticationManager,
				authenticationFilterSecurityContextHolderStrategyRef);
		createFormLoginFilter(sessionStrategy, authenticationManager,
				authenticationFilterSecurityContextHolderStrategyRef, authenticationFilterSecurityContextRepositoryRef);
		createOAuth2ClientFilters(sessionStrategy, requestCache, authenticationManager,
				authenticationFilterSecurityContextRepositoryRef, authenticationFilterSecurityContextHolderStrategyRef);
		createSaml2LoginFilter(authenticationManager, authenticationFilterSecurityContextRepositoryRef);
		createX509Filter(authenticationManager, authenticationFilterSecurityContextHolderStrategyRef);
		createJeeFilter(authenticationManager, authenticationFilterSecurityContextHolderStrategyRef);
		createLogoutFilter(authenticationFilterSecurityContextHolderStrategyRef);
		createSaml2LogoutFilter(authenticationFilterSecurityContextHolderStrategyRef);
		createLoginPageFilterIfNeeded();
		createUserDetailsServiceFactory();
		createExceptionTranslationFilter(authenticationFilterSecurityContextHolderStrategyRef);
	}

	void createRememberMeFilter(BeanReference authenticationManager,
			BeanMetadataElement authenticationFilterSecurityContextHolderStrategyRef) {
		// Parse remember me before logout as RememberMeServices is also a LogoutHandler
		// implementation.
		Element rememberMeElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.REMEMBER_ME);
		if (rememberMeElt != null) {
			String key = rememberMeElt.getAttribute(ATT_KEY);
			if (!StringUtils.hasText(key)) {
				key = createKey();
			}
			RememberMeBeanDefinitionParser rememberMeParser = new RememberMeBeanDefinitionParser(key,
					authenticationManager, authenticationFilterSecurityContextHolderStrategyRef);
			this.rememberMeFilter = rememberMeParser.parse(rememberMeElt, this.pc);
			this.rememberMeServicesId = rememberMeParser.getRememberMeServicesId();
			createRememberMeProvider(key);
		}
	}

	private void createRememberMeProvider(String key) {
		RootBeanDefinition provider = new RootBeanDefinition(RememberMeAuthenticationProvider.class);
		provider.setSource(this.rememberMeFilter.getSource());
		provider.getConstructorArgumentValues().addGenericArgumentValue(key);
		String id = this.pc.getReaderContext().generateBeanName(provider);
		this.pc.registerBeanComponent(new BeanComponentDefinition(provider, id));
		this.rememberMeProviderRef = new RuntimeBeanReference(id);
	}

	void createFormLoginFilter(BeanReference sessionStrategy, BeanReference authManager,
			BeanMetadataElement authenticationFilterSecurityContextHolderStrategyRef,
			BeanReference authenticationFilterSecurityContextRepositoryRef) {
		Element formLoginElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.FORM_LOGIN);
		RootBeanDefinition formFilter = null;
		if (formLoginElt != null || this.autoConfig) {
			FormLoginBeanDefinitionParser parser = new FormLoginBeanDefinitionParser("/login", "POST",
					AUTHENTICATION_PROCESSING_FILTER_CLASS, this.requestCache, sessionStrategy,
					this.allowSessionCreation, this.portMapper, this.portResolver);
			parser.parse(formLoginElt, this.pc);
			formFilter = parser.getFilterBean();
			this.formEntryPoint = parser.getEntryPointBean();
			this.loginProcessingUrl = parser.getLoginProcessingUrl();
			this.formLoginPage = parser.getLoginPage();
		}
		if (formFilter != null) {
			formFilter.getPropertyValues().addPropertyValue("allowSessionCreation", this.allowSessionCreation);
			formFilter.getPropertyValues().addPropertyValue("authenticationManager", authManager);
			if (authenticationFilterSecurityContextRepositoryRef != null) {
				formFilter.getPropertyValues().addPropertyValue("securityContextRepository",
						authenticationFilterSecurityContextRepositoryRef);
			}
			formFilter.getPropertyValues().addPropertyValue("securityContextHolderStrategy",
					authenticationFilterSecurityContextHolderStrategyRef);
			// Id is required by login page filter
			this.formFilterId = this.pc.getReaderContext().generateBeanName(formFilter);
			this.pc.registerBeanComponent(new BeanComponentDefinition(formFilter, this.formFilterId));
			injectRememberMeServicesRef(formFilter, this.rememberMeServicesId);
		}
	}

	void createOAuth2ClientFilters(BeanReference sessionStrategy, BeanReference requestCache,
			BeanReference authenticationManager, BeanReference authenticationFilterSecurityContextRepositoryRef,
			BeanMetadataElement authenticationFilterSecurityContextHolderStrategy) {
		createOAuth2LoginFilter(sessionStrategy, authenticationManager,
				authenticationFilterSecurityContextRepositoryRef, authenticationFilterSecurityContextHolderStrategy);
		createOAuth2ClientFilter(requestCache, authenticationManager, authenticationFilterSecurityContextRepositoryRef,
				authenticationFilterSecurityContextHolderStrategy);
		registerOAuth2ClientPostProcessors();
	}

	void createOAuth2LoginFilter(BeanReference sessionStrategy, BeanReference authManager,
			BeanReference authenticationFilterSecurityContextRepositoryRef,
			BeanMetadataElement authenticationFilterSecurityContextHolderStrategy) {
		Element oauth2LoginElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.OAUTH2_LOGIN);
		if (oauth2LoginElt == null) {
			return;
		}
		this.oauth2LoginEnabled = true;
		OAuth2LoginBeanDefinitionParser parser = new OAuth2LoginBeanDefinitionParser(this.requestCache, this.portMapper,
				this.portResolver, sessionStrategy, this.allowSessionCreation,
				authenticationFilterSecurityContextHolderStrategy);
		BeanDefinition oauth2LoginFilterBean = parser.parse(oauth2LoginElt, this.pc);
		BeanDefinition defaultAuthorizedClientRepository = parser.getDefaultAuthorizedClientRepository();
		registerDefaultAuthorizedClientRepositoryIfNecessary(defaultAuthorizedClientRepository);
		oauth2LoginFilterBean.getPropertyValues().addPropertyValue("authenticationManager", authManager);
		if (authenticationFilterSecurityContextRepositoryRef != null) {
			oauth2LoginFilterBean.getPropertyValues().addPropertyValue("securityContextRepository",
					authenticationFilterSecurityContextRepositoryRef);
		}

		// retrieve the other bean result
		BeanDefinition oauth2LoginAuthProvider = parser.getOAuth2LoginAuthenticationProvider();
		this.oauth2AuthorizationRequestRedirectFilter = parser.getOAuth2AuthorizationRequestRedirectFilter();
		this.oauth2LoginEntryPoint = parser.getOAuth2LoginAuthenticationEntryPoint();

		// generate bean name to be registered
		String oauth2LoginAuthProviderId = this.pc.getReaderContext().generateBeanName(oauth2LoginAuthProvider);
		this.oauth2LoginFilterId = this.pc.getReaderContext().generateBeanName(oauth2LoginFilterBean);
		String oauth2AuthorizationRequestRedirectFilterId = this.pc.getReaderContext()
				.generateBeanName(this.oauth2AuthorizationRequestRedirectFilter);
		this.oauth2LoginLinks = parser.getOAuth2LoginLinks();

		// register the component
		this.pc.registerBeanComponent(new BeanComponentDefinition(oauth2LoginFilterBean, this.oauth2LoginFilterId));
		this.pc.registerBeanComponent(new BeanComponentDefinition(this.oauth2AuthorizationRequestRedirectFilter,
				oauth2AuthorizationRequestRedirectFilterId));
		this.pc.registerBeanComponent(new BeanComponentDefinition(oauth2LoginAuthProvider, oauth2LoginAuthProviderId));

		this.oauth2LoginAuthenticationProviderRef = new RuntimeBeanReference(oauth2LoginAuthProviderId);

		// oidc provider
		BeanDefinition oauth2LoginOidcAuthProvider = parser.getOAuth2LoginOidcAuthenticationProvider();
		String oauth2LoginOidcAuthProviderId = this.pc.getReaderContext().generateBeanName(oauth2LoginOidcAuthProvider);
		this.pc.registerBeanComponent(
				new BeanComponentDefinition(oauth2LoginOidcAuthProvider, oauth2LoginOidcAuthProviderId));
		this.oauth2LoginOidcAuthenticationProviderRef = new RuntimeBeanReference(oauth2LoginOidcAuthProviderId);
	}

	void createOAuth2ClientFilter(BeanReference requestCache, BeanReference authenticationManager,
			BeanReference authenticationFilterSecurityContextRepositoryRef,
			BeanMetadataElement authenticationFilterSecurityContextHolderStrategy) {
		Element oauth2ClientElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.OAUTH2_CLIENT);
		if (oauth2ClientElt == null) {
			return;
		}
		this.oauth2ClientEnabled = true;
		OAuth2ClientBeanDefinitionParser parser = new OAuth2ClientBeanDefinitionParser(requestCache,
				authenticationManager, authenticationFilterSecurityContextRepositoryRef,
				authenticationFilterSecurityContextHolderStrategy);
		parser.parse(oauth2ClientElt, this.pc);
		BeanDefinition defaultAuthorizedClientRepository = parser.getDefaultAuthorizedClientRepository();
		registerDefaultAuthorizedClientRepositoryIfNecessary(defaultAuthorizedClientRepository);
		this.authorizationRequestRedirectFilter = parser.getAuthorizationRequestRedirectFilter();
		String authorizationRequestRedirectFilterId = this.pc.getReaderContext()
				.generateBeanName(this.authorizationRequestRedirectFilter);
		this.pc.registerBeanComponent(new BeanComponentDefinition(this.authorizationRequestRedirectFilter,
				authorizationRequestRedirectFilterId));
		this.authorizationCodeGrantFilter = parser.getAuthorizationCodeGrantFilter();
		String authorizationCodeGrantFilterId = this.pc.getReaderContext()
				.generateBeanName(this.authorizationCodeGrantFilter);
		this.pc.registerBeanComponent(
				new BeanComponentDefinition(this.authorizationCodeGrantFilter, authorizationCodeGrantFilterId));
		BeanDefinition authorizationCodeAuthenticationProvider = parser.getAuthorizationCodeAuthenticationProvider();
		String authorizationCodeAuthenticationProviderId = this.pc.getReaderContext()
				.generateBeanName(authorizationCodeAuthenticationProvider);
		this.pc.registerBeanComponent(new BeanComponentDefinition(authorizationCodeAuthenticationProvider,
				authorizationCodeAuthenticationProviderId));
		this.authorizationCodeAuthenticationProviderRef = new RuntimeBeanReference(
				authorizationCodeAuthenticationProviderId);
	}

	void registerDefaultAuthorizedClientRepositoryIfNecessary(BeanDefinition defaultAuthorizedClientRepository) {
		if (!this.defaultAuthorizedClientRepositoryRegistered && defaultAuthorizedClientRepository != null) {
			String authorizedClientRepositoryId = this.pc.getReaderContext()
					.generateBeanName(defaultAuthorizedClientRepository);
			this.pc.registerBeanComponent(
					new BeanComponentDefinition(defaultAuthorizedClientRepository, authorizedClientRepositoryId));
			this.defaultAuthorizedClientRepositoryRegistered = true;
		}
	}

	private void registerOAuth2ClientPostProcessors() {
		if (!this.oauth2LoginEnabled && !this.oauth2ClientEnabled) {
			return;
		}
		boolean webmvcPresent = ClassUtils.isPresent("org.springframework.web.servlet.DispatcherServlet",
				getClass().getClassLoader());
		if (webmvcPresent) {
			this.pc.getReaderContext()
					.registerWithGeneratedName(new RootBeanDefinition(OAuth2ClientWebMvcSecurityPostProcessor.class));
		}
	}

	private void createSaml2LoginFilter(BeanReference authenticationManager,
			BeanReference authenticationFilterSecurityContextRepositoryRef) {
		Element saml2LoginElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.SAML2_LOGIN);
		if (saml2LoginElt == null) {
			return;
		}
		Saml2LoginBeanDefinitionParser parser = new Saml2LoginBeanDefinitionParser(this.csrfIgnoreRequestMatchers,
				this.portMapper, this.portResolver, this.requestCache, this.allowSessionCreation, authenticationManager,
				authenticationFilterSecurityContextRepositoryRef, this.authenticationProviders,
				this.defaultEntryPointMappings);
		BeanDefinition saml2WebSsoAuthenticationFilter = parser.parse(saml2LoginElt, this.pc);
		this.saml2AuthorizationRequestFilter = parser.getSaml2WebSsoAuthenticationRequestFilter();

		this.saml2AuthenticationFilterId = this.pc.getReaderContext().generateBeanName(saml2WebSsoAuthenticationFilter);
		this.saml2AuthenticationRequestFilterId = this.pc.getReaderContext()
				.generateBeanName(this.saml2AuthorizationRequestFilter);
		this.saml2AuthenticationUrlToProviderName = parser.getSaml2AuthenticationUrlToProviderName();

		// register the component
		this.pc.registerBeanComponent(
				new BeanComponentDefinition(saml2WebSsoAuthenticationFilter, this.saml2AuthenticationFilterId));
		this.pc.registerBeanComponent(new BeanComponentDefinition(this.saml2AuthorizationRequestFilter,
				this.saml2AuthenticationRequestFilterId));
	}

	private void injectRememberMeServicesRef(RootBeanDefinition bean, String rememberMeServicesId) {
		if (rememberMeServicesId != null) {
			bean.getPropertyValues().addPropertyValue("rememberMeServices",
					new RuntimeBeanReference(rememberMeServicesId));
		}
	}

	void createBasicFilter(BeanReference authManager,
			BeanMetadataElement authenticationFilterSecurityContextHolderStrategyRef) {
		Element basicAuthElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.BASIC_AUTH);
		if (basicAuthElt == null && !this.autoConfig) {
			// No basic auth, do nothing
			return;
		}
		String realm = this.httpElt.getAttribute(ATT_REALM);
		if (!StringUtils.hasText(realm)) {
			realm = DEF_REALM;
		}
		BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder.rootBeanDefinition(BasicAuthenticationFilter.class);
		String entryPointId;
		if (basicAuthElt != null) {
			if (StringUtils.hasText(basicAuthElt.getAttribute(ATT_ENTRY_POINT_REF))) {
				this.basicEntryPoint = new RuntimeBeanReference(basicAuthElt.getAttribute(ATT_ENTRY_POINT_REF));
			}
			injectAuthenticationDetailsSource(basicAuthElt, filterBuilder);
		}
		if (this.basicEntryPoint == null) {
			RootBeanDefinition entryPoint = new RootBeanDefinition(BasicAuthenticationEntryPoint.class);
			entryPoint.setSource(this.pc.extractSource(this.httpElt));
			entryPoint.getPropertyValues().addPropertyValue("realmName", realm);
			entryPointId = this.pc.getReaderContext().generateBeanName(entryPoint);
			this.pc.registerBeanComponent(new BeanComponentDefinition(entryPoint, entryPointId));
			this.basicEntryPoint = new RuntimeBeanReference(entryPointId);
		}
		filterBuilder.addConstructorArgValue(authManager);
		filterBuilder.addConstructorArgValue(this.basicEntryPoint);
		filterBuilder.addPropertyValue("securityContextHolderStrategy",
				authenticationFilterSecurityContextHolderStrategyRef);
		this.basicFilter = filterBuilder.getBeanDefinition();
	}

	void createBearerTokenAuthenticationFilter(BeanReference authManager,
			BeanMetadataElement authenticationFilterSecurityContextHolderStrategyRef) {
		Element resourceServerElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.OAUTH2_RESOURCE_SERVER);
		if (resourceServerElt == null) {
			// No resource server, do nothing
			return;
		}
		OAuth2ResourceServerBeanDefinitionParser resourceServerBuilder = new OAuth2ResourceServerBeanDefinitionParser(
				authManager, this.authenticationProviders, this.defaultEntryPointMappings,
				this.defaultDeniedHandlerMappings, this.csrfIgnoreRequestMatchers,
				authenticationFilterSecurityContextHolderStrategyRef);
		this.bearerTokenAuthenticationFilter = resourceServerBuilder.parse(resourceServerElt, this.pc);
	}

	void createX509Filter(BeanReference authManager,
			BeanMetadataElement authenticationFilterSecurityContextHolderStrategyRef) {
		Element x509Elt = DomUtils.getChildElementByTagName(this.httpElt, Elements.X509);
		RootBeanDefinition filter = null;
		if (x509Elt != null) {
			BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder
					.rootBeanDefinition(X509AuthenticationFilter.class);
			filterBuilder.getRawBeanDefinition().setSource(this.pc.extractSource(x509Elt));
			filterBuilder.addPropertyValue("authenticationManager", authManager);
			filterBuilder.addPropertyValue("securityContextHolderStrategy",
					authenticationFilterSecurityContextHolderStrategyRef);
			String regex = x509Elt.getAttribute("subject-principal-regex");
			if (StringUtils.hasText(regex)) {
				BeanDefinitionBuilder extractor = BeanDefinitionBuilder
						.rootBeanDefinition(SubjectDnX509PrincipalExtractor.class);
				extractor.addPropertyValue("subjectDnRegex", regex);
				filterBuilder.addPropertyValue("principalExtractor", extractor.getBeanDefinition());
			}
			injectAuthenticationDetailsSource(x509Elt, filterBuilder);
			filter = (RootBeanDefinition) filterBuilder.getBeanDefinition();
			createPrauthEntryPoint(x509Elt);
			createX509Provider();
		}
		this.x509Filter = filter;
	}

	private void injectAuthenticationDetailsSource(Element elt, BeanDefinitionBuilder filterBuilder) {
		String authDetailsSourceRef = elt.getAttribute(AuthenticationConfigBuilder.ATT_AUTH_DETAILS_SOURCE_REF);
		if (StringUtils.hasText(authDetailsSourceRef)) {
			filterBuilder.addPropertyReference("authenticationDetailsSource", authDetailsSourceRef);
		}
	}

	private void createX509Provider() {
		Element x509Elt = DomUtils.getChildElementByTagName(this.httpElt, Elements.X509);
		BeanDefinition provider = new RootBeanDefinition(PreAuthenticatedAuthenticationProvider.class);
		RootBeanDefinition uds = new RootBeanDefinition();
		uds.setFactoryBeanName(BeanIds.USER_DETAILS_SERVICE_FACTORY);
		uds.setFactoryMethodName("authenticationUserDetailsService");
		uds.getConstructorArgumentValues().addGenericArgumentValue(x509Elt.getAttribute(ATT_USER_SERVICE_REF));
		provider.getPropertyValues().addPropertyValue("preAuthenticatedUserDetailsService", uds);
		this.x509ProviderRef = new RuntimeBeanReference(this.pc.getReaderContext().registerWithGeneratedName(provider));
	}

	private void createPrauthEntryPoint(Element source) {
		if (this.preAuthEntryPoint == null) {
			this.preAuthEntryPoint = new RootBeanDefinition(Http403ForbiddenEntryPoint.class);
			this.preAuthEntryPoint.setSource(this.pc.extractSource(source));
		}
	}

	void createJeeFilter(BeanReference authManager,
			BeanMetadataElement authenticationFilterSecurityContextHolderStrategyRef) {
		Element jeeElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.JEE);
		RootBeanDefinition filter = null;
		if (jeeElt != null) {
			BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder
					.rootBeanDefinition(J2eePreAuthenticatedProcessingFilter.class);
			filterBuilder.getRawBeanDefinition().setSource(this.pc.extractSource(jeeElt));
			filterBuilder.addPropertyValue("authenticationManager", authManager);
			filterBuilder.addPropertyValue("securityContextHolderStrategy",
					authenticationFilterSecurityContextHolderStrategyRef);
			BeanDefinitionBuilder adsBldr = BeanDefinitionBuilder
					.rootBeanDefinition(J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource.class);
			adsBldr.addPropertyValue("userRoles2GrantedAuthoritiesMapper",
					new RootBeanDefinition(SimpleAttributes2GrantedAuthoritiesMapper.class));
			String roles = jeeElt.getAttribute(ATT_MAPPABLE_ROLES);
			Assert.hasLength(roles, "roles is expected to have length");
			BeanDefinitionBuilder rolesBuilder = BeanDefinitionBuilder.rootBeanDefinition(StringUtils.class);
			rolesBuilder.addConstructorArgValue(roles);
			rolesBuilder.setFactoryMethod("commaDelimitedListToSet");
			RootBeanDefinition mappableRolesRetriever = new RootBeanDefinition(SimpleMappableAttributesRetriever.class);
			mappableRolesRetriever.getPropertyValues().addPropertyValue("mappableAttributes",
					rolesBuilder.getBeanDefinition());
			adsBldr.addPropertyValue("mappableRolesRetriever", mappableRolesRetriever);
			filterBuilder.addPropertyValue("authenticationDetailsSource", adsBldr.getBeanDefinition());
			filter = (RootBeanDefinition) filterBuilder.getBeanDefinition();
			createPrauthEntryPoint(jeeElt);
			createJeeProvider();
		}
		this.jeeFilter = filter;
	}

	private void createJeeProvider() {
		Element jeeElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.JEE);
		BeanDefinition provider = new RootBeanDefinition(PreAuthenticatedAuthenticationProvider.class);
		RootBeanDefinition uds;
		if (StringUtils.hasText(jeeElt.getAttribute(ATT_USER_SERVICE_REF))) {
			uds = new RootBeanDefinition();
			uds.setFactoryBeanName(BeanIds.USER_DETAILS_SERVICE_FACTORY);
			uds.setFactoryMethodName("authenticationUserDetailsService");
			uds.getConstructorArgumentValues().addGenericArgumentValue(jeeElt.getAttribute(ATT_USER_SERVICE_REF));
		}
		else {
			uds = new RootBeanDefinition(PreAuthenticatedGrantedAuthoritiesUserDetailsService.class);
		}
		provider.getPropertyValues().addPropertyValue("preAuthenticatedUserDetailsService", uds);
		this.jeeProviderRef = new RuntimeBeanReference(this.pc.getReaderContext().registerWithGeneratedName(provider));
	}

	void createLoginPageFilterIfNeeded() {
		boolean needLoginPage = this.formFilterId != null || this.oauth2LoginFilterId != null;
		// If no login page has been defined, add in the default page generator.
		if (needLoginPage && this.formLoginPage == null) {
			this.logger.info("No login page configured. The default internal one will be used. Use the '"
					+ FormLoginBeanDefinitionParser.ATT_LOGIN_PAGE + "' attribute to set the URL of the login page.");
			BeanDefinitionBuilder loginPageFilter = BeanDefinitionBuilder
					.rootBeanDefinition(DefaultLoginPageGeneratingFilter.class);
			loginPageFilter.addPropertyValue("resolveHiddenInputs", new CsrfTokenHiddenInputFunction());

			BeanDefinitionBuilder logoutPageFilter = BeanDefinitionBuilder
					.rootBeanDefinition(DefaultLogoutPageGeneratingFilter.class);
			logoutPageFilter.addPropertyValue("resolveHiddenInputs", new CsrfTokenHiddenInputFunction());
			if (this.formFilterId != null) {
				loginPageFilter.addConstructorArgReference(this.formFilterId);
				loginPageFilter.addPropertyValue("authenticationUrl", this.loginProcessingUrl);
			}
			if (this.oauth2LoginFilterId != null) {
				loginPageFilter.addPropertyValue("Oauth2LoginEnabled", true);
				loginPageFilter.addPropertyValue("Oauth2AuthenticationUrlToClientName", this.oauth2LoginLinks);
			}
			if (this.saml2AuthenticationFilterId != null) {
				loginPageFilter.addPropertyValue("saml2LoginEnabled", true);
				loginPageFilter.addPropertyValue("saml2AuthenticationUrlToProviderName",
						this.saml2AuthenticationUrlToProviderName);
			}
			this.loginPageGenerationFilter = loginPageFilter.getBeanDefinition();
			this.logoutPageGenerationFilter = logoutPageFilter.getBeanDefinition();
		}
	}

	void createLogoutFilter(BeanMetadataElement authenticationFilterSecurityContextHolderStrategyRef) {
		Element logoutElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.LOGOUT);
		if (logoutElt != null || this.autoConfig) {
			String formLoginPage = this.formLoginPage;
			if (formLoginPage == null) {
				formLoginPage = DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL;
			}
			LogoutBeanDefinitionParser logoutParser = new LogoutBeanDefinitionParser(formLoginPage,
					this.rememberMeServicesId, this.csrfLogoutHandler,
					authenticationFilterSecurityContextHolderStrategyRef);
			this.logoutFilter = logoutParser.parse(logoutElt, this.pc);
			this.logoutHandlers = logoutParser.getLogoutHandlers();
			this.logoutSuccessHandler = logoutParser.getLogoutSuccessHandler();
		}
	}

	private void createSaml2LogoutFilter(BeanMetadataElement authenticationFilterSecurityContextHolderStrategyRef) {
		Element saml2LogoutElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.SAML2_LOGOUT);
		if (saml2LogoutElt == null) {
			return;
		}
		Saml2LogoutBeanDefinitionParser parser = new Saml2LogoutBeanDefinitionParser(this.logoutHandlers,
				this.logoutSuccessHandler, authenticationFilterSecurityContextHolderStrategyRef);
		parser.parse(saml2LogoutElt, this.pc);
		BeanDefinition saml2LogoutFilter = parser.getLogoutFilter();
		BeanDefinition saml2LogoutRequestFilter = parser.getLogoutRequestFilter();
		BeanDefinition saml2LogoutResponseFilter = parser.getLogoutResponseFilter();
		this.saml2LogoutFilterId = this.pc.getReaderContext().generateBeanName(saml2LogoutFilter);
		this.saml2LogoutRequestFilterId = this.pc.getReaderContext().generateBeanName(saml2LogoutRequestFilter);
		this.saml2LogoutResponseFilterId = this.pc.getReaderContext().generateBeanName(saml2LogoutResponseFilter);

		// register the component
		this.pc.registerBeanComponent(new BeanComponentDefinition(saml2LogoutFilter, this.saml2LogoutFilterId));
		this.pc.registerBeanComponent(
				new BeanComponentDefinition(saml2LogoutRequestFilter, this.saml2LogoutRequestFilterId));
		this.pc.registerBeanComponent(
				new BeanComponentDefinition(saml2LogoutResponseFilter, this.saml2LogoutResponseFilterId));
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	ManagedList getLogoutHandlers() {
		if (this.logoutHandlers == null && this.rememberMeProviderRef != null) {
			this.logoutHandlers = new ManagedList();
			if (this.csrfLogoutHandler != null) {
				this.logoutHandlers.add(this.csrfLogoutHandler);
			}
			this.logoutHandlers.add(new RuntimeBeanReference(this.rememberMeServicesId));
			this.logoutHandlers.add(new RootBeanDefinition(SecurityContextLogoutHandler.class));
		}

		return this.logoutHandlers;
	}

	BeanMetadataElement getEntryPointBean() {
		return this.mainEntryPoint;
	}

	BeanMetadataElement getAccessDeniedHandlerBean() {
		return this.accessDeniedHandler;
	}

	List<BeanDefinition> getCsrfIgnoreRequestMatchers() {
		return this.csrfIgnoreRequestMatchers;
	}

	void createAnonymousFilter(BeanMetadataElement authenticationFilterSecurityContextHolderStrategyRef) {
		Element anonymousElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.ANONYMOUS);
		if (anonymousElt != null && "false".equals(anonymousElt.getAttribute("enabled"))) {
			return;
		}
		String grantedAuthority = null;
		String username = null;
		String key = null;
		Object source = this.pc.extractSource(this.httpElt);
		if (anonymousElt != null) {
			grantedAuthority = anonymousElt.getAttribute("granted-authority");
			username = anonymousElt.getAttribute("username");
			key = anonymousElt.getAttribute(ATT_KEY);
			source = this.pc.extractSource(anonymousElt);
		}
		if (!StringUtils.hasText(grantedAuthority)) {
			grantedAuthority = "ROLE_ANONYMOUS";
		}
		if (!StringUtils.hasText(username)) {
			username = "anonymousUser";
		}
		if (!StringUtils.hasText(key)) {
			// Generate a random key for the Anonymous provider
			key = createKey();
		}
		this.anonymousFilter = new RootBeanDefinition(AnonymousAuthenticationFilter.class);
		this.anonymousFilter.getConstructorArgumentValues().addIndexedArgumentValue(0, key);
		this.anonymousFilter.getConstructorArgumentValues().addIndexedArgumentValue(1, username);
		this.anonymousFilter.getConstructorArgumentValues().addIndexedArgumentValue(2,
				AuthorityUtils.commaSeparatedStringToAuthorityList(grantedAuthority));
		this.anonymousFilter.getPropertyValues().addPropertyValue("securityContextHolderStrategy",
				authenticationFilterSecurityContextHolderStrategyRef);
		this.anonymousFilter.setSource(source);
		RootBeanDefinition anonymousProviderBean = new RootBeanDefinition(AnonymousAuthenticationProvider.class);
		anonymousProviderBean.getConstructorArgumentValues().addIndexedArgumentValue(0, key);
		anonymousProviderBean.setSource(this.anonymousFilter.getSource());
		String id = this.pc.getReaderContext().generateBeanName(anonymousProviderBean);
		this.pc.registerBeanComponent(new BeanComponentDefinition(anonymousProviderBean, id));
		this.anonymousProviderRef = new RuntimeBeanReference(id);
	}

	private String createKey() {
		SecureRandom random = new SecureRandom();
		return Long.toString(random.nextLong());
	}

	void createExceptionTranslationFilter(BeanMetadataElement authenticationFilterSecurityContextHolderStrategyRef) {
		BeanDefinitionBuilder etfBuilder = BeanDefinitionBuilder.rootBeanDefinition(ExceptionTranslationFilter.class);
		this.accessDeniedHandler = createAccessDeniedHandler(this.httpElt, this.pc);
		etfBuilder.addPropertyValue("accessDeniedHandler", this.accessDeniedHandler);
		Assert.state(this.requestCache != null, "No request cache found");
		this.mainEntryPoint = selectEntryPoint();
		etfBuilder.addConstructorArgValue(this.mainEntryPoint);
		etfBuilder.addConstructorArgValue(this.requestCache);
		etfBuilder.addPropertyValue("securityContextHolderStrategy",
				authenticationFilterSecurityContextHolderStrategyRef);
		this.etf = etfBuilder.getBeanDefinition();
	}

	private BeanMetadataElement createAccessDeniedHandler(Element element, ParserContext pc) {
		Element accessDeniedElt = DomUtils.getChildElementByTagName(element, Elements.ACCESS_DENIED_HANDLER);
		BeanDefinitionBuilder accessDeniedHandler = BeanDefinitionBuilder
				.rootBeanDefinition(AccessDeniedHandlerImpl.class);
		if (accessDeniedElt != null) {
			String errorPage = accessDeniedElt.getAttribute("error-page");
			String ref = accessDeniedElt.getAttribute("ref");
			if (StringUtils.hasText(errorPage)) {
				if (StringUtils.hasText(ref)) {
					pc.getReaderContext()
							.error("The attribute " + ATT_ACCESS_DENIED_ERROR_PAGE
									+ " cannot be used together with the 'ref' attribute within <"
									+ Elements.ACCESS_DENIED_HANDLER + ">", pc.extractSource(accessDeniedElt));

				}
				accessDeniedHandler.addPropertyValue("errorPage", errorPage);
				return accessDeniedHandler.getBeanDefinition();
			}
			if (StringUtils.hasText(ref)) {
				return new RuntimeBeanReference(ref);
			}
		}
		if (this.defaultDeniedHandlerMappings.isEmpty()) {
			return accessDeniedHandler.getBeanDefinition();
		}
		if (this.defaultDeniedHandlerMappings.size() == 1) {
			return this.defaultDeniedHandlerMappings.values().iterator().next();
		}
		accessDeniedHandler = BeanDefinitionBuilder
				.rootBeanDefinition(RequestMatcherDelegatingAccessDeniedHandler.class);
		accessDeniedHandler.addConstructorArgValue(this.defaultDeniedHandlerMappings);
		accessDeniedHandler
				.addConstructorArgValue(BeanDefinitionBuilder.rootBeanDefinition(AccessDeniedHandlerImpl.class));
		return accessDeniedHandler.getBeanDefinition();
	}

	private BeanMetadataElement selectEntryPoint() {
		// We need to establish the main entry point.
		// First check if a custom entry point bean is set
		String customEntryPoint = this.httpElt.getAttribute(ATT_ENTRY_POINT_REF);
		if (StringUtils.hasText(customEntryPoint)) {
			return new RuntimeBeanReference(customEntryPoint);
		}
		if (!this.defaultEntryPointMappings.isEmpty()) {
			if (this.defaultEntryPointMappings.size() == 1) {
				return this.defaultEntryPointMappings.values().iterator().next();
			}
			BeanDefinitionBuilder delegatingEntryPoint = BeanDefinitionBuilder
					.rootBeanDefinition(DelegatingAuthenticationEntryPoint.class);
			delegatingEntryPoint.addConstructorArgValue(this.defaultEntryPointMappings);
			return delegatingEntryPoint.getBeanDefinition();
		}
		Element basicAuthElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.BASIC_AUTH);
		Element formLoginElt = DomUtils.getChildElementByTagName(this.httpElt, Elements.FORM_LOGIN);
		// Basic takes precedence if explicit element is used and no others are configured
		if (basicAuthElt != null && formLoginElt == null && this.oauth2LoginEntryPoint == null) {
			return this.basicEntryPoint;
		}
		if (this.formFilterId != null) {
			// If form login was enabled through element and Oauth2 login was enabled from
			// element then use form login (gh-6802)
			if (formLoginElt != null && this.oauth2LoginEntryPoint != null) {
				return this.formEntryPoint;
			}
			// If form login was enabled through auto-config, and Oauth2 login & Saml2
			// login was not
			// enabled then use form login
			if (this.oauth2LoginEntryPoint == null) {
				return this.formEntryPoint;
			}
		}
		// If X.509 or JEE have been enabled, use the preauth entry point.
		if (this.preAuthEntryPoint != null) {
			return this.preAuthEntryPoint;
		}
		// OAuth2 entry point will not be null if only 1 client registration
		if (this.oauth2LoginEntryPoint != null) {
			return this.oauth2LoginEntryPoint;
		}
		this.pc.getReaderContext().error("No AuthenticationEntryPoint could be established. Please "
				+ "make sure you have a login mechanism configured through the namespace (such as form-login) or "
				+ "specify a custom AuthenticationEntryPoint with the '" + ATT_ENTRY_POINT_REF + "' attribute ",
				this.pc.extractSource(this.httpElt));
		return null;
	}

	private void createUserDetailsServiceFactory() {
		if (this.pc.getRegistry().containsBeanDefinition(BeanIds.USER_DETAILS_SERVICE_FACTORY)) {
			// Multiple <http> case
			return;
		}
		RootBeanDefinition bean = new RootBeanDefinition(UserDetailsServiceFactoryBean.class);
		bean.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
		this.pc.registerBeanComponent(new BeanComponentDefinition(bean, BeanIds.USER_DETAILS_SERVICE_FACTORY));
	}

	List<OrderDecorator> getFilters() {
		List<OrderDecorator> filters = new ArrayList<>();
		if (this.anonymousFilter != null) {
			filters.add(new OrderDecorator(this.anonymousFilter, SecurityFilters.ANONYMOUS_FILTER));
		}
		if (this.rememberMeFilter != null) {
			filters.add(new OrderDecorator(this.rememberMeFilter, SecurityFilters.REMEMBER_ME_FILTER));
		}
		if (this.logoutFilter != null) {
			filters.add(new OrderDecorator(this.logoutFilter, SecurityFilters.LOGOUT_FILTER));
		}
		if (this.x509Filter != null) {
			filters.add(new OrderDecorator(this.x509Filter, SecurityFilters.X509_FILTER));
		}
		if (this.jeeFilter != null) {
			filters.add(new OrderDecorator(this.jeeFilter, SecurityFilters.PRE_AUTH_FILTER));
		}
		if (this.formFilterId != null) {
			filters.add(
					new OrderDecorator(new RuntimeBeanReference(this.formFilterId), SecurityFilters.FORM_LOGIN_FILTER));
		}
		if (this.oauth2LoginFilterId != null) {
			filters.add(new OrderDecorator(new RuntimeBeanReference(this.oauth2LoginFilterId),
					SecurityFilters.OAUTH2_LOGIN_FILTER));
			filters.add(new OrderDecorator(this.oauth2AuthorizationRequestRedirectFilter,
					SecurityFilters.OAUTH2_AUTHORIZATION_REQUEST_FILTER));
		}
		if (this.loginPageGenerationFilter != null) {
			filters.add(new OrderDecorator(this.loginPageGenerationFilter, SecurityFilters.LOGIN_PAGE_FILTER));
			filters.add(new OrderDecorator(this.logoutPageGenerationFilter, SecurityFilters.LOGOUT_PAGE_FILTER));
		}
		if (this.basicFilter != null) {
			filters.add(new OrderDecorator(this.basicFilter, SecurityFilters.BASIC_AUTH_FILTER));
		}
		if (this.bearerTokenAuthenticationFilter != null) {
			filters.add(
					new OrderDecorator(this.bearerTokenAuthenticationFilter, SecurityFilters.BEARER_TOKEN_AUTH_FILTER));
		}
		if (this.authorizationCodeGrantFilter != null) {
			filters.add(new OrderDecorator(this.authorizationRequestRedirectFilter,
					SecurityFilters.OAUTH2_AUTHORIZATION_REQUEST_FILTER.getOrder() + 1));
			filters.add(new OrderDecorator(this.authorizationCodeGrantFilter,
					SecurityFilters.OAUTH2_AUTHORIZATION_CODE_GRANT_FILTER));
		}
		if (this.saml2AuthenticationFilterId != null) {
			filters.add(new OrderDecorator(new RuntimeBeanReference(this.saml2AuthenticationFilterId),
					SecurityFilters.SAML2_AUTHENTICATION_FILTER));
			filters.add(new OrderDecorator(new RuntimeBeanReference(this.saml2AuthenticationRequestFilterId),
					SecurityFilters.SAML2_AUTHENTICATION_REQUEST_FILTER));
		}
		if (this.saml2LogoutFilterId != null) {
			filters.add(new OrderDecorator(new RuntimeBeanReference(this.saml2LogoutFilterId),
					SecurityFilters.SAML2_LOGOUT_FILTER));
			filters.add(new OrderDecorator(new RuntimeBeanReference(this.saml2LogoutRequestFilterId),
					SecurityFilters.SAML2_LOGOUT_REQUEST_FILTER));
			filters.add(new OrderDecorator(new RuntimeBeanReference(this.saml2LogoutResponseFilterId),
					SecurityFilters.SAML2_LOGOUT_RESPONSE_FILTER));
		}
		filters.add(new OrderDecorator(this.etf, SecurityFilters.EXCEPTION_TRANSLATION_FILTER));
		return filters;
	}

	List<BeanReference> getProviders() {
		List<BeanReference> providers = new ArrayList<>();
		if (this.anonymousProviderRef != null) {
			providers.add(this.anonymousProviderRef);
		}
		if (this.rememberMeProviderRef != null) {
			providers.add(this.rememberMeProviderRef);
		}
		if (this.x509ProviderRef != null) {
			providers.add(this.x509ProviderRef);
		}
		if (this.jeeProviderRef != null) {
			providers.add(this.jeeProviderRef);
		}
		if (this.oauth2LoginAuthenticationProviderRef != null) {
			providers.add(this.oauth2LoginAuthenticationProviderRef);
		}
		if (this.oauth2LoginOidcAuthenticationProviderRef != null) {
			providers.add(this.oauth2LoginOidcAuthenticationProviderRef);
		}
		if (this.authorizationCodeAuthenticationProviderRef != null) {
			providers.add(this.authorizationCodeAuthenticationProviderRef);
		}
		providers.addAll(this.authenticationProviders);
		return providers;
	}

	private static class CsrfTokenHiddenInputFunction implements Function<HttpServletRequest, Map<String, String>> {

		@Override
		public Map<String, String> apply(HttpServletRequest request) {
			CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
			if (token == null) {
				return Collections.emptyMap();
			}
			return Collections.singletonMap(token.getParameterName(), token.getToken());
		}

	}

}
