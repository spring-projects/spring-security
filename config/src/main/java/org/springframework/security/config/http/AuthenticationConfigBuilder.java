package org.springframework.security.config.http;

import static org.springframework.security.config.http.SecurityFilters.*;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.PropertyValues;
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
import org.springframework.security.core.authority.mapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleMappableAttributesRetriever;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;
import org.springframework.security.web.authentication.preauth.j2ee.J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Handles creation of authentication mechanism filters and related beans for &lt;http&gt; parsing.
 *
 * @author Luke Taylor
 * @since 3.0
 */
final class AuthenticationConfigBuilder {
    private final Log logger = LogFactory.getLog(getClass());

    private static final String ATT_REALM = "realm";
    private static final String DEF_REALM = "Spring Security Application";

    static final String OPEN_ID_AUTHENTICATION_PROCESSING_FILTER_CLASS = "org.springframework.security.openid.OpenIDAuthenticationFilter";
    static final String OPEN_ID_AUTHENTICATION_PROVIDER_CLASS = "org.springframework.security.openid.OpenIDAuthenticationProvider";
    private static final String OPEN_ID_CONSUMER_CLASS = "org.springframework.security.openid.OpenID4JavaConsumer";
    static final String OPEN_ID_ATTRIBUTE_CLASS = "org.springframework.security.openid.OpenIDAttribute";
    private static final String OPEN_ID_ATTRIBUTE_FACTORY_CLASS = "org.springframework.security.openid.RegexBasedAxFetchListFactory";
    static final String AUTHENTICATION_PROCESSING_FILTER_CLASS = "org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter";

    static final String ATT_AUTH_DETAILS_SOURCE_REF = "authentication-details-source-ref";

    private static final String ATT_AUTO_CONFIG = "auto-config";

    private static final String ATT_ACCESS_DENIED_PAGE = "access-denied-page";
    private static final String ATT_ACCESS_DENIED_ERROR_PAGE = "error-page";
    private static final String ATT_ENTRY_POINT_REF = "entry-point-ref";

    private static final String ATT_USER_SERVICE_REF = "user-service-ref";


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
    private RootBeanDefinition formFilter;
    private BeanDefinition formEntryPoint;
    private RootBeanDefinition openIDFilter;
    private BeanDefinition openIDEntryPoint;
    private BeanReference openIDProviderRef;
    private String formFilterId = null;
    private String openIDFilterId = null;
    private BeanDefinition x509Filter;
    private BeanReference x509ProviderRef;
    private BeanDefinition jeeFilter;
    private BeanReference jeeProviderRef;
    private RootBeanDefinition preAuthEntryPoint;

    private BeanDefinition logoutFilter;
    private BeanDefinition loginPageGenerationFilter;
    private BeanDefinition etf;
    private final BeanReference requestCache;

    final SecureRandom random;

    public AuthenticationConfigBuilder(Element element, ParserContext pc, SessionCreationPolicy sessionPolicy,
            BeanReference requestCache, BeanReference authenticationManager, BeanReference sessionStrategy) {
        this.httpElt = element;
        this.pc = pc;
        this.requestCache = requestCache;
        autoConfig = "true".equals(element.getAttribute(ATT_AUTO_CONFIG));
        this.allowSessionCreation = sessionPolicy != SessionCreationPolicy.never
                && sessionPolicy != SessionCreationPolicy.stateless;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            // Shouldn't happen...
            throw new RuntimeException("Failed find SHA1PRNG algorithm!");
        }

        createAnonymousFilter();
        createRememberMeFilter(authenticationManager);
        createBasicFilter(authenticationManager);
        createFormLoginFilter(sessionStrategy, authenticationManager);
        createOpenIDLoginFilter(sessionStrategy, authenticationManager);
        createX509Filter(authenticationManager);
        createJeeFilter(authenticationManager);
        createLogoutFilter();
        createLoginPageFilterIfNeeded();
        createUserDetailsServiceFactory();
        createExceptionTranslationFilter();

    }

    void createRememberMeFilter(BeanReference authenticationManager) {
        final String ATT_KEY = "key";
        final String DEF_KEY = "SpringSecured";

        // Parse remember me before logout as RememberMeServices is also a LogoutHandler implementation.
        Element rememberMeElt = DomUtils.getChildElementByTagName(httpElt, Elements.REMEMBER_ME);

        if (rememberMeElt != null) {
            String key = rememberMeElt.getAttribute(ATT_KEY);

            if (!StringUtils.hasText(key)) {
                key = DEF_KEY;
            }

            rememberMeFilter = new RememberMeBeanDefinitionParser(key).parse(rememberMeElt, pc);
            rememberMeFilter.getPropertyValues().addPropertyValue("authenticationManager", authenticationManager);
            rememberMeServicesId = ((RuntimeBeanReference) rememberMeFilter.getPropertyValues().getPropertyValue("rememberMeServices").getValue()).getBeanName();
            createRememberMeProvider(key);
        }
    }

    private void createRememberMeProvider(String key) {
        RootBeanDefinition provider = new RootBeanDefinition(RememberMeAuthenticationProvider.class);
        provider.setSource(rememberMeFilter.getSource());

        provider.getPropertyValues().addPropertyValue("key", key);

        String id = pc.getReaderContext().generateBeanName(provider);
        pc.registerBeanComponent(new BeanComponentDefinition(provider, id));

        rememberMeProviderRef = new RuntimeBeanReference(id);
    }

    void createFormLoginFilter(BeanReference sessionStrategy, BeanReference authManager) {

        Element formLoginElt = DomUtils.getChildElementByTagName(httpElt, Elements.FORM_LOGIN);

        if (formLoginElt != null || autoConfig) {
            FormLoginBeanDefinitionParser parser = new FormLoginBeanDefinitionParser("/j_spring_security_check",
                    AUTHENTICATION_PROCESSING_FILTER_CLASS, requestCache, sessionStrategy, allowSessionCreation);

            parser.parse(formLoginElt, pc);
            formFilter = parser.getFilterBean();
            formEntryPoint = parser.getEntryPointBean();
        }

        if (formFilter != null) {
            formFilter.getPropertyValues().addPropertyValue("allowSessionCreation", allowSessionCreation);
            formFilter.getPropertyValues().addPropertyValue("authenticationManager", authManager);

            // Id is required by login page filter
            formFilterId = pc.getReaderContext().generateBeanName(formFilter);
            pc.registerBeanComponent(new BeanComponentDefinition(formFilter, formFilterId));
            injectRememberMeServicesRef(formFilter, rememberMeServicesId);
        }
    }

    void createOpenIDLoginFilter(BeanReference sessionStrategy, BeanReference authManager) {
        Element openIDLoginElt = DomUtils.getChildElementByTagName(httpElt, Elements.OPENID_LOGIN);

        if (openIDLoginElt != null) {
            FormLoginBeanDefinitionParser parser = new FormLoginBeanDefinitionParser("/j_spring_openid_security_check",
                    OPEN_ID_AUTHENTICATION_PROCESSING_FILTER_CLASS, requestCache, sessionStrategy, allowSessionCreation);

            parser.parse(openIDLoginElt, pc);
            openIDFilter = parser.getFilterBean();
            openIDEntryPoint = parser.getEntryPointBean();

            List<Element> attrExElts = DomUtils.getChildElementsByTagName(openIDLoginElt, Elements.OPENID_ATTRIBUTE_EXCHANGE);

            if (!attrExElts.isEmpty()) {
                // Set up the consumer with the required attribute list
                BeanDefinitionBuilder consumerBldr = BeanDefinitionBuilder.rootBeanDefinition(OPEN_ID_CONSUMER_CLASS);
                BeanDefinitionBuilder axFactory = BeanDefinitionBuilder.rootBeanDefinition(OPEN_ID_ATTRIBUTE_FACTORY_CLASS);
                ManagedMap<String, ManagedList<BeanDefinition>> axMap = new ManagedMap<String, ManagedList<BeanDefinition>>();

                for (Element attrExElt : attrExElts) {
                    String identifierMatch = attrExElt.getAttribute("identifier-match");

                    if (!StringUtils.hasText(identifierMatch)) {
                        if (attrExElts.size() > 1) {
                            pc.getReaderContext().error("You must supply an identifier-match attribute if using more" +
                                    " than one " + Elements.OPENID_ATTRIBUTE_EXCHANGE + " element", attrExElt);
                        }
                        // Match anything
                        identifierMatch = ".*";
                    }

                    axMap.put(identifierMatch, parseOpenIDAttributes(attrExElt));
                }
                axFactory.addConstructorArgValue(axMap);

                consumerBldr.addConstructorArgValue(axFactory.getBeanDefinition());
                openIDFilter.getPropertyValues().addPropertyValue("consumer", consumerBldr.getBeanDefinition());
            }
        }

        if (openIDFilter != null) {
            openIDFilter.getPropertyValues().addPropertyValue("allowSessionCreation", allowSessionCreation);
            openIDFilter.getPropertyValues().addPropertyValue("authenticationManager", authManager);
            // Required by login page filter
            openIDFilterId = pc.getReaderContext().generateBeanName(openIDFilter);
            pc.registerBeanComponent(new BeanComponentDefinition(openIDFilter, openIDFilterId));
            injectRememberMeServicesRef(openIDFilter, rememberMeServicesId);

            createOpenIDProvider();
        }
    }

    private ManagedList<BeanDefinition> parseOpenIDAttributes(Element attrExElt) {
        ManagedList<BeanDefinition> attributes = new ManagedList<BeanDefinition> ();
        for (Element attElt : DomUtils.getChildElementsByTagName(attrExElt, Elements.OPENID_ATTRIBUTE)) {
            String name = attElt.getAttribute("name");
            String type = attElt.getAttribute("type");
            String required = attElt.getAttribute("required");
            String count = attElt.getAttribute("count");
            BeanDefinitionBuilder attrBldr = BeanDefinitionBuilder.rootBeanDefinition(OPEN_ID_ATTRIBUTE_CLASS);
            attrBldr.addConstructorArgValue(name);
            attrBldr.addConstructorArgValue(type);
            if (StringUtils.hasLength(required)) {
                attrBldr.addPropertyValue("required", Boolean.valueOf(required));
            }

            if (StringUtils.hasLength(count)) {
                attrBldr.addPropertyValue("count", Integer.parseInt(count));
            }
            attributes.add(attrBldr.getBeanDefinition());
        }

        return attributes;
    }

    private void createOpenIDProvider() {
        Element openIDLoginElt = DomUtils.getChildElementByTagName(httpElt, Elements.OPENID_LOGIN);
        BeanDefinitionBuilder openIDProviderBuilder =
            BeanDefinitionBuilder.rootBeanDefinition(OPEN_ID_AUTHENTICATION_PROVIDER_CLASS);

        RootBeanDefinition uds = new RootBeanDefinition();
        uds.setFactoryBeanName(BeanIds.USER_DETAILS_SERVICE_FACTORY);
        uds.setFactoryMethodName("authenticationUserDetailsService");
        uds.getConstructorArgumentValues().addGenericArgumentValue(openIDLoginElt.getAttribute(ATT_USER_SERVICE_REF));

        openIDProviderBuilder.addPropertyValue("authenticationUserDetailsService", uds);

        BeanDefinition openIDProvider = openIDProviderBuilder.getBeanDefinition();
        openIDProviderRef = new RuntimeBeanReference(pc.getReaderContext().registerWithGeneratedName(openIDProvider));
    }

    private void injectRememberMeServicesRef(RootBeanDefinition bean, String rememberMeServicesId) {
        if (rememberMeServicesId != null) {
            bean.getPropertyValues().addPropertyValue("rememberMeServices", new RuntimeBeanReference(rememberMeServicesId));
        }
    }

    void createBasicFilter(BeanReference authManager) {
        Element basicAuthElt = DomUtils.getChildElementByTagName(httpElt, Elements.BASIC_AUTH);

        if (basicAuthElt == null && !autoConfig) {
            // No basic auth, do nothing
            return;
        }

        String realm = httpElt.getAttribute(ATT_REALM);
        if (!StringUtils.hasText(realm)) {
            realm = DEF_REALM;
        }

        BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder.rootBeanDefinition(BasicAuthenticationFilter.class);

        String entryPointId;

        if (basicAuthElt != null) {
            if (StringUtils.hasText(basicAuthElt.getAttribute(ATT_ENTRY_POINT_REF))) {
                basicEntryPoint = new RuntimeBeanReference(basicAuthElt.getAttribute(ATT_ENTRY_POINT_REF));
            }

            injectAuthenticationDetailsSource(basicAuthElt, filterBuilder);

        }

        if (basicEntryPoint == null) {
            RootBeanDefinition entryPoint = new RootBeanDefinition(BasicAuthenticationEntryPoint.class);
            entryPoint.setSource(pc.extractSource(httpElt));
            entryPoint.getPropertyValues().addPropertyValue("realmName", realm);
            entryPointId = pc.getReaderContext().generateBeanName(entryPoint);
            pc.registerBeanComponent(new BeanComponentDefinition(entryPoint, entryPointId));
            basicEntryPoint = new RuntimeBeanReference(entryPointId);
        }

        filterBuilder.addPropertyValue("authenticationManager", authManager);
        filterBuilder.addPropertyValue("authenticationEntryPoint", basicEntryPoint);
        basicFilter = filterBuilder.getBeanDefinition();
    }

    void createX509Filter(BeanReference authManager) {
        Element x509Elt = DomUtils.getChildElementByTagName(httpElt, Elements.X509);
        RootBeanDefinition filter = null;

        if (x509Elt != null) {
            BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder.rootBeanDefinition(X509AuthenticationFilter.class);
            filterBuilder.getRawBeanDefinition().setSource(pc.extractSource(x509Elt));
            filterBuilder.addPropertyValue("authenticationManager", authManager);

            String regex = x509Elt.getAttribute("subject-principal-regex");

            if (StringUtils.hasText(regex)) {
                BeanDefinitionBuilder extractor = BeanDefinitionBuilder.rootBeanDefinition(SubjectDnX509PrincipalExtractor.class);
                extractor.addPropertyValue("subjectDnRegex", regex);

                filterBuilder.addPropertyValue("principalExtractor", extractor.getBeanDefinition());
            }

            injectAuthenticationDetailsSource(x509Elt, filterBuilder);

            filter = (RootBeanDefinition) filterBuilder.getBeanDefinition();
            createPrauthEntryPoint(x509Elt);

            createX509Provider();
        }

        x509Filter = filter;
    }

    private void injectAuthenticationDetailsSource(Element elt, BeanDefinitionBuilder filterBuilder) {
        String authDetailsSourceRef = elt.getAttribute(AuthenticationConfigBuilder.ATT_AUTH_DETAILS_SOURCE_REF);

        if (StringUtils.hasText(authDetailsSourceRef)) {
            filterBuilder.addPropertyReference("authenticationDetailsSource", authDetailsSourceRef);
        }
    }

    private void createX509Provider() {
        Element x509Elt = DomUtils.getChildElementByTagName(httpElt, Elements.X509);
        BeanDefinition provider = new RootBeanDefinition(PreAuthenticatedAuthenticationProvider.class);

        RootBeanDefinition uds = new RootBeanDefinition();
        uds.setFactoryBeanName(BeanIds.USER_DETAILS_SERVICE_FACTORY);
        uds.setFactoryMethodName("authenticationUserDetailsService");
        uds.getConstructorArgumentValues().addGenericArgumentValue(x509Elt.getAttribute(ATT_USER_SERVICE_REF));

        provider.getPropertyValues().addPropertyValue("preAuthenticatedUserDetailsService", uds);

        x509ProviderRef = new RuntimeBeanReference(pc.getReaderContext().registerWithGeneratedName(provider));
    }

    private void createPrauthEntryPoint(Element source) {
        if (preAuthEntryPoint == null) {
            preAuthEntryPoint = new RootBeanDefinition(Http403ForbiddenEntryPoint.class);
            preAuthEntryPoint.setSource(pc.extractSource(source));
        }
    }

    void createJeeFilter(BeanReference authManager) {
        final String ATT_MAPPABLE_ROLES = "mappable-roles";

        Element jeeElt = DomUtils.getChildElementByTagName(httpElt, Elements.JEE);
        RootBeanDefinition filter = null;

        if (jeeElt != null) {
            BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder.rootBeanDefinition(J2eePreAuthenticatedProcessingFilter.class);
            filterBuilder.getRawBeanDefinition().setSource(pc.extractSource(jeeElt));
            filterBuilder.addPropertyValue("authenticationManager", authManager);

            BeanDefinitionBuilder adsBldr = BeanDefinitionBuilder.rootBeanDefinition(J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource.class);
            adsBldr.addPropertyValue("userRoles2GrantedAuthoritiesMapper", new RootBeanDefinition(SimpleAttributes2GrantedAuthoritiesMapper.class));

            String roles = jeeElt.getAttribute(ATT_MAPPABLE_ROLES);
            Assert.state(StringUtils.hasText(roles));
            BeanDefinitionBuilder rolesBuilder = BeanDefinitionBuilder.rootBeanDefinition(StringUtils.class);
            rolesBuilder.addConstructorArgValue(roles);
            rolesBuilder.setFactoryMethod("commaDelimitedListToSet");

            RootBeanDefinition mappableRolesRetriever = new RootBeanDefinition(SimpleMappableAttributesRetriever.class);
            mappableRolesRetriever.getPropertyValues().addPropertyValue("mappableAttributes", rolesBuilder.getBeanDefinition());
            adsBldr.addPropertyValue("mappableRolesRetriever", mappableRolesRetriever);
            filterBuilder.addPropertyValue("authenticationDetailsSource", adsBldr.getBeanDefinition());

            filter = (RootBeanDefinition) filterBuilder.getBeanDefinition();

            createPrauthEntryPoint(jeeElt);
            createJeeProvider();
        }

        jeeFilter = filter;
    }

    private void createJeeProvider() {
        Element jeeElt = DomUtils.getChildElementByTagName(httpElt, Elements.JEE);
        BeanDefinition provider = new RootBeanDefinition(PreAuthenticatedAuthenticationProvider.class);

        RootBeanDefinition uds;
        if (StringUtils.hasText(jeeElt.getAttribute(ATT_USER_SERVICE_REF))) {
            uds = new RootBeanDefinition();
            uds.setFactoryBeanName(BeanIds.USER_DETAILS_SERVICE_FACTORY);
            uds.setFactoryMethodName("authenticationUserDetailsService");
            uds.getConstructorArgumentValues().addGenericArgumentValue(jeeElt.getAttribute(ATT_USER_SERVICE_REF));
        } else {
            uds = new RootBeanDefinition(PreAuthenticatedGrantedAuthoritiesUserDetailsService.class);
        }

        provider.getPropertyValues().addPropertyValue("preAuthenticatedUserDetailsService", uds);

        jeeProviderRef = new RuntimeBeanReference(pc.getReaderContext().registerWithGeneratedName(provider));
    }

    void createLoginPageFilterIfNeeded() {
        boolean needLoginPage = formFilter != null || openIDFilter != null;
        String formLoginPage = getLoginFormUrl(formEntryPoint);
        String openIDLoginPage = getLoginFormUrl(openIDEntryPoint);

        // If no login page has been defined, add in the default page generator.
        if (needLoginPage && formLoginPage == null && openIDLoginPage == null) {
            logger.info("No login page configured. The default internal one will be used. Use the '"
                     + FormLoginBeanDefinitionParser.ATT_LOGIN_PAGE + "' attribute to set the URL of the login page.");
            BeanDefinitionBuilder loginPageFilter =
                BeanDefinitionBuilder.rootBeanDefinition(DefaultLoginPageGeneratingFilter.class);

            if (formFilter != null) {
                loginPageFilter.addConstructorArgReference(formFilterId);
            }

            if (openIDFilter != null) {
                loginPageFilter.addConstructorArgReference(openIDFilterId);
            }

            loginPageGenerationFilter = loginPageFilter.getBeanDefinition();
        }
    }

    void createLogoutFilter() {
        Element logoutElt = DomUtils.getChildElementByTagName(httpElt, Elements.LOGOUT);
        if (logoutElt != null || autoConfig) {
            logoutFilter = new LogoutBeanDefinitionParser(rememberMeServicesId).parse(logoutElt, pc);
        }
    }

    void createAnonymousFilter() {
        Element anonymousElt = DomUtils.getChildElementByTagName(httpElt, Elements.ANONYMOUS);

        if (anonymousElt != null && "false".equals(anonymousElt.getAttribute("enabled"))) {
            return;
        }

        String grantedAuthority = null;
        String username = null;
        String key = null;
        Object source = pc.extractSource(httpElt);

        if (anonymousElt != null) {
            grantedAuthority = anonymousElt.getAttribute("granted-authority");
            username = anonymousElt.getAttribute("username");
            key = anonymousElt.getAttribute("key");
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

        anonymousFilter = new RootBeanDefinition(AnonymousAuthenticationFilter.class);

        PropertyValue keyPV = new PropertyValue("key", key);
        anonymousFilter.setSource(source);
        anonymousFilter.getPropertyValues().addPropertyValue("userAttribute", username + "," + grantedAuthority);
        anonymousFilter.getPropertyValues().addPropertyValue(keyPV);

        RootBeanDefinition anonymousProviderBean = new RootBeanDefinition(AnonymousAuthenticationProvider.class);
        anonymousProviderBean.setSource(anonymousFilter.getSource());
        anonymousProviderBean.getPropertyValues().addPropertyValue(keyPV);
        String id = pc.getReaderContext().generateBeanName(anonymousProviderBean);
        pc.registerBeanComponent(new BeanComponentDefinition(anonymousProviderBean, id));

        anonymousProviderRef = new RuntimeBeanReference(id);

    }

    void createExceptionTranslationFilter() {
        BeanDefinitionBuilder etfBuilder = BeanDefinitionBuilder.rootBeanDefinition(ExceptionTranslationFilter.class);
        etfBuilder.addPropertyValue("accessDeniedHandler", createAccessDeniedHandler(httpElt, pc));
        assert requestCache != null;
        etfBuilder.addPropertyValue("requestCache", requestCache);
        etfBuilder.addPropertyValue("authenticationEntryPoint", selectEntryPoint());

        etf = etfBuilder.getBeanDefinition();
    }

    private BeanMetadataElement createAccessDeniedHandler(Element element, ParserContext pc) {
        String accessDeniedPage = element.getAttribute(ATT_ACCESS_DENIED_PAGE);
        WebConfigUtils.validateHttpRedirect(accessDeniedPage, pc, pc.extractSource(element));
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

    private BeanMetadataElement selectEntryPoint() {
        // We need to establish the main entry point.
        // First check if a custom entry point bean is set
        String customEntryPoint = httpElt.getAttribute(ATT_ENTRY_POINT_REF);

        if (StringUtils.hasText(customEntryPoint)) {
            return new RuntimeBeanReference(customEntryPoint);
        }

        Element basicAuthElt = DomUtils.getChildElementByTagName(httpElt, Elements.BASIC_AUTH);
        Element formLoginElt = DomUtils.getChildElementByTagName(httpElt, Elements.FORM_LOGIN);
        Element openIDLoginElt = DomUtils.getChildElementByTagName(httpElt, Elements.OPENID_LOGIN);
        // Basic takes precedence if explicit element is used and no others are configured
        if (basicAuthElt != null && formLoginElt == null && openIDLoginElt == null) {
            return basicEntryPoint;
        }

        // If formLogin has been enabled either through an element or auto-config, then it is used if no openID login page
        // has been set.
        String formLoginPage = getLoginFormUrl(formEntryPoint);
        String openIDLoginPage = getLoginFormUrl(openIDEntryPoint);

        if (formLoginPage != null && openIDLoginPage != null) {
            pc.getReaderContext().error("Only one login-page can be defined, either for OpenID or form-login, " +
                    "but not both.", pc.extractSource(openIDLoginElt));
        }

        if (formFilter != null && openIDLoginPage == null) {
            return formEntryPoint;
        }

        // Otherwise use OpenID if enabled
        if (openIDFilter != null) {
            return openIDEntryPoint;
        }

        // If X.509 or JEE have been enabled, use the preauth entry point.
        if (preAuthEntryPoint != null) {
            return preAuthEntryPoint;
        }

        pc.getReaderContext().error("No AuthenticationEntryPoint could be established. Please " +
                "make sure you have a login mechanism configured through the namespace (such as form-login) or " +
                "specify a custom AuthenticationEntryPoint with the '" + ATT_ENTRY_POINT_REF+ "' attribute ",
                pc.extractSource(httpElt));
        return null;
    }

    private String getLoginFormUrl(BeanDefinition entryPoint) {
        if (entryPoint == null) {
            return null;
        }

        PropertyValues pvs = entryPoint.getPropertyValues();
        PropertyValue pv = pvs.getPropertyValue("loginFormUrl");
        if (pv == null) {
             return null;
        }

        // If the login URL is the default one, then it is assumed not to have been set explicitly
        if (DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL.equals(pv.getValue())) {
            return null;
        }

        return (String) pv.getValue();
    }

    private void createUserDetailsServiceFactory() {
        if (pc.getRegistry().containsBeanDefinition(BeanIds.USER_DETAILS_SERVICE_FACTORY)) {
            // Multiple <http> case
            return;
        }
        RootBeanDefinition bean = new RootBeanDefinition(UserDetailsServiceFactoryBean.class);
        bean.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
        pc.getReaderContext().getRegistry().registerBeanDefinition(BeanIds.USER_DETAILS_SERVICE_FACTORY, bean);
    }

    List<OrderDecorator> getFilters() {
        List<OrderDecorator> filters = new ArrayList<OrderDecorator>();

        if (anonymousFilter != null) {
            filters.add(new OrderDecorator(anonymousFilter, ANONYMOUS_FILTER));
        }

        if (rememberMeFilter != null) {
            filters.add(new OrderDecorator(rememberMeFilter, REMEMBER_ME_FILTER));
        }

        if (logoutFilter != null) {
            filters.add(new OrderDecorator(logoutFilter, LOGOUT_FILTER));
        }

        if (x509Filter != null) {
            filters.add(new OrderDecorator(x509Filter, X509_FILTER));
        }

        if (jeeFilter != null) {
            filters.add(new OrderDecorator(jeeFilter, PRE_AUTH_FILTER));
        }

        if (formFilter != null) {
            filters.add(new OrderDecorator(formFilter, FORM_LOGIN_FILTER));
        }

        if (openIDFilter != null) {
            filters.add(new OrderDecorator(openIDFilter, OPENID_FILTER));
        }

        if (loginPageGenerationFilter != null) {
            filters.add(new OrderDecorator(loginPageGenerationFilter, LOGIN_PAGE_FILTER));
        }

        if (basicFilter != null) {
            filters.add(new OrderDecorator(basicFilter, BASIC_AUTH_FILTER));
        }

        filters.add(new OrderDecorator(etf, EXCEPTION_TRANSLATION_FILTER));

        return filters;
    }

    List<BeanReference> getProviders() {
        List<BeanReference> providers = new ArrayList<BeanReference>();

        if (anonymousProviderRef != null) {
            providers.add(anonymousProviderRef);
        }

        if (rememberMeProviderRef != null) {
            providers.add(rememberMeProviderRef);
        }

        if (openIDProviderRef != null) {
            providers.add(openIDProviderRef);
        }

        if (x509ProviderRef != null) {
            providers.add(x509ProviderRef);
        }

        if (jeeProviderRef != null) {
            providers.add(jeeProviderRef);
        }

        return providers;
    }

}
