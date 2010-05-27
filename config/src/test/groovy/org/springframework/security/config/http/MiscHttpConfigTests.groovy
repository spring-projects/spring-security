package org.springframework.security.config.http;

import java.util.Collection;
import java.util.Map;
import java.util.Iterator;

import javax.servlet.Filter
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.BeansException
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.context.support.AbstractXmlApplicationContext
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.util.FieldUtils;
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.config.MockUserServiceBeanPostProcessor;
import org.springframework.security.config.PostProcessedMockUserDetailsService;
import org.springframework.security.web.*;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.*
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.context.*;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.session.SessionManagementFilter;

import groovy.lang.Closure;

class MiscHttpConfigTests extends AbstractHttpConfigTests {
    def 'Minimal configuration parses'() {
        setup:
        xml.http {
            'http-basic'()
        }
        createAppContext()
    }

    def httpAutoConfigSetsUpCorrectFilterList() {
        when:
        xml.http('auto-config': 'true')
        createAppContext()

        then:
        filtersMatchExpectedAutoConfigList('/anyurl');
    }

    void filtersMatchExpectedAutoConfigList(String url) {
        def filterList = getFilters(url);
        Iterator<Filter> filters = filterList.iterator();

        assert filters.next() instanceof SecurityContextPersistenceFilter
        assert filters.next() instanceof LogoutFilter
        Object authProcFilter = filters.next();
        assert authProcFilter instanceof UsernamePasswordAuthenticationFilter
        assert filters.next() instanceof DefaultLoginPageGeneratingFilter
        assert filters.next() instanceof BasicAuthenticationFilter
        assert filters.next() instanceof RequestCacheAwareFilter
        assert filters.next() instanceof SecurityContextHolderAwareRequestFilter
        assert filters.next() instanceof AnonymousAuthenticationFilter
        assert filters.next() instanceof SessionManagementFilter
        assert filters.next() instanceof ExceptionTranslationFilter
        Object fsiObj = filters.next();
        assert fsiObj instanceof FilterSecurityInterceptor
        def fsi = (FilterSecurityInterceptor) fsiObj;
        assert fsi.isObserveOncePerRequest()
    }

    def filterListShouldBeEmptyForPatternWithNoFilters() {
        xml.http(pattern: '/unprotected', secured: 'false')
        httpAutoConfig() {}
        createAppContext()

        expect:
        getFilters("/unprotected").size() == 0
    }

    def regexPathsWorkCorrectly() {
        xml.http(pattern: '\\A\\/[a-z]+', secured: 'false', 'request-matcher': 'regex')
        httpAutoConfig() {}
        createAppContext()

        expect:
        getFilters('/imlowercase').size() == 0
        filtersMatchExpectedAutoConfigList('/MixedCase');
    }

    def ciRegexPathsWorkCorrectly() {
        when:
        xml.http(pattern: '\\A\\/[a-z]+', secured: 'false', 'request-matcher': 'ciRegex')
        httpAutoConfig() {}
        createAppContext()

        then:
        getFilters('/imMixedCase').size() == 0
        filtersMatchExpectedAutoConfigList('/Im_caught_by_the_Universal_Match');
    }

    // SEC-1152
    def anonymousFilterIsAddedByDefault() {
        xml.http {
            'form-login'()
        }
        createAppContext()

        expect:
        getFilters("/anything")[5] instanceof AnonymousAuthenticationFilter
    }

    def anonymousFilterIsRemovedIfDisabledFlagSet() {
        xml.http {
            'form-login'()
            'anonymous'(enabled: 'false')
        }
        createAppContext()

        expect:
        !(getFilters("/anything").get(5) instanceof AnonymousAuthenticationFilter)
    }

    def anonymousCustomAttributesAreSetCorrectly() {
        xml.http {
            'form-login'()
            'anonymous'(username: 'joe', 'granted-authority':'anonymity', key: 'customKey')
        }
        createAppContext()

        AnonymousAuthenticationFilter filter = getFilter(AnonymousAuthenticationFilter);

        expect:
        'customKey' == filter.getKey()
        'joe' == filter.userAttribute.password
        'anonymity' == filter.userAttribute.authorities[0].authority
    }

    def httpMethodMatchIsSupported() {
        httpAutoConfig {
            interceptUrl '/secure*', 'DELETE', 'ROLE_SUPERVISOR'
            interceptUrl '/secure*', 'POST', 'ROLE_A,ROLE_B'
            interceptUrl '/**', 'ROLE_C'
        }
        createAppContext()

        def fids = getFilter(FilterSecurityInterceptor).getSecurityMetadataSource();
        def attrs = fids.getAttributes(createFilterinvocation("/secure", "POST"));

        expect:
        attrs.size() == 2
        attrs.contains(new SecurityConfig("ROLE_A"))
        attrs.contains(new SecurityConfig("ROLE_B"))
    }

    def oncePerRequestAttributeIsSupported() {
        xml.http('once-per-request': 'false') {
            'http-basic'()
        }
        createAppContext()

        expect:
        !getFilter(FilterSecurityInterceptor).isObserveOncePerRequest()
    }

    def httpBasicSupportsSeparateEntryPoint() {
        xml.http() {
            'http-basic'('entry-point-ref': 'ep')
        }
        bean('ep', BasicAuthenticationEntryPoint.class.name, ['realmName':'whocares'],[:])
        createAppContext();

        def baf = getFilter(BasicAuthenticationFilter)
        def etf = getFilter(ExceptionTranslationFilter)
        def ep = appContext.getBean("ep")

        expect:
        baf.authenticationEntryPoint == ep
        // Since no other authentication system is in use, this should also end up on the ETF
        etf.authenticationEntryPoint == ep
    }

    def interceptUrlWithRequiresChannelAddsChannelFilterToStack() {
        httpAutoConfig {
            'intercept-url'(pattern: '/**', 'requires-channel': 'https')
        }
        createAppContext();
        List filters = getFilters("/someurl");

        expect:
        filters.size() == AUTO_CONFIG_FILTERS + 1
        filters[0] instanceof ChannelProcessingFilter
    }

    def portMappingsAreParsedCorrectly() {
        httpAutoConfig {
            'port-mappings'() {
                'port-mapping'(http: '9080', https: '9443')
            }
        }
        createAppContext();

        def pm = (appContext.getBeansOfType(PortMapperImpl).values() as List)[0];

        expect:
        pm.getTranslatedPortMappings().size() == 1
        pm.lookupHttpPort(9443) == 9080
        pm.lookupHttpsPort(9080) == 9443
    }

    def externalFiltersAreTreatedCorrectly() {
        httpAutoConfig {
            'custom-filter'(position: 'FIRST', ref: '${customFilterRef}')
            'custom-filter'(after: 'LOGOUT_FILTER', ref: 'userFilter')
            'custom-filter'(before: 'SECURITY_CONTEXT_FILTER', ref: 'userFilter1')
        }
        bean('phc', PropertyPlaceholderConfigurer)
        bean('userFilter', SecurityContextHolderAwareRequestFilter)
        bean('userFilter1', SecurityContextPersistenceFilter)

        System.setProperty('customFilterRef', 'userFilter')
        createAppContext();

        def filters = getFilters("/someurl");

        expect:
        AUTO_CONFIG_FILTERS + 3 == filters.size();
        filters[0] instanceof SecurityContextHolderAwareRequestFilter
        filters[1] instanceof SecurityContextPersistenceFilter
        filters[4] instanceof SecurityContextHolderAwareRequestFilter
        filters[1] instanceof SecurityContextPersistenceFilter
    }

    def twoFiltersWithSameOrderAreRejected() {
        when:
        httpAutoConfig {
            'custom-filter'(position: 'LOGOUT_FILTER', ref: 'userFilter')
        }
        bean('userFilter', SecurityContextHolderAwareRequestFilter)
        createAppContext();

        then:
        thrown(BeanDefinitionParsingException)
    }

    def x509SupportAddsFilterAtExpectedPosition() {
        httpAutoConfig {
            x509()
        }
        createAppContext()

        def filters = getFilters("/someurl")

        expect:
        getFilters("/someurl")[2] instanceof X509AuthenticationFilter
    }

    def x509SubjectPrincipalRegexCanBeSetUsingPropertyPlaceholder() {
        httpAutoConfig {
            x509('subject-principal-regex':'${subject-principal-regex}')
        }
        bean('phc', PropertyPlaceholderConfigurer.class.name)
        System.setProperty("subject-principal-regex", "uid=(.*),");
        createAppContext()
        def filter = getFilter(X509AuthenticationFilter)

        expect:
        filter.principalExtractor.subjectDnPattern.pattern() == "uid=(.*),"
    }

    def invalidLogoutSuccessUrlIsDetected() {
        when:
        xml.http {
            'form-login'()
            'logout'('logout-success-url': 'noLeadingSlash')
        }
        createAppContext()

        then:
        BeanCreationException e = thrown()
    }

    def invalidLogoutUrlIsDetected() {
        when:
        xml.http {
            'logout'('logout-url': 'noLeadingSlash')
            'form-login'()
        }
        createAppContext()

        then:
        BeanCreationException e = thrown();
    }

    def logoutSuccessHandlerIsSetCorrectly() {
        xml.http {
            'form-login'()
            'logout'('success-handler-ref': 'logoutHandler')
        }
        bean('logoutHandler', SimpleUrlLogoutSuccessHandler)
        createAppContext()

        LogoutFilter filter = getFilter(LogoutFilter);

        expect:
        FieldUtils.getFieldValue(filter, "logoutSuccessHandler") == appContext.getBean("logoutHandler")
    }

    def externalRequestCacheIsConfiguredCorrectly() {
        httpAutoConfig {
            'request-cache'(ref: 'cache')
        }
        bean('cache', HttpSessionRequestCache.class.name)
        createAppContext()

        expect:
        appContext.getBean("cache") == getFilter(ExceptionTranslationFilter.class).requestCache
    }

    def customEntryPointIsSupported() {
        xml.http('auto-config': 'true', 'entry-point-ref': 'entryPoint') {}
        bean('entryPoint', MockEntryPoint.class.name)
        createAppContext()

        expect:
        getFilter(ExceptionTranslationFilter).getAuthenticationEntryPoint() instanceof MockEntryPoint
    }

    /**
     * See SEC-750. If the http security post processor causes beans to be instantiated too eagerly, they way miss
     * additional processing. In this method we have a UserDetailsService which is referenced from the namespace
     * and also has a post processor registered which will modify it.
     */
    def httpElementDoesntInterfereWithBeanPostProcessing() {
        httpAutoConfig {}
        xml.'authentication-manager'() {
            'authentication-provider'('user-service-ref': 'myUserService')
        }
        bean('myUserService', PostProcessedMockUserDetailsService)
        bean('beanPostProcessor', MockUserServiceBeanPostProcessor)
        createAppContext("")

        expect:
        appContext.getBean("myUserService").getPostProcessorWasHere() == "Hello from the post processor!"
    }

    /* SEC-934 */
    def supportsTwoIdenticalInterceptUrls() {
        httpAutoConfig {
            interceptUrl ('/someUrl', 'ROLE_A')
            interceptUrl ('/someUrl', 'ROLE_B')
        }
        createAppContext()
        def fis = getFilter(FilterSecurityInterceptor)
        def fids = fis.securityMetadataSource
        Collection attrs = fids.getAttributes(createFilterinvocation("/someurl", null));

        expect:
        attrs.size() == 1
        attrs.contains(new SecurityConfig("ROLE_B"))
    }

    def supportsExternallyDefinedSecurityContextRepository() {
        xml.http('create-session': 'always', 'security-context-repository-ref': 'repo') {
            'http-basic'()
        }
        bean('repo', HttpSessionSecurityContextRepository)
        createAppContext()

        def filter = getFilter(SecurityContextPersistenceFilter)

        expect:
        filter.repo == appContext.getBean('repo')
        filter.forceEagerSessionCreation == true
    }

    def expressionBasedAccessAllowsAndDeniesAccessAsExpected() {
        setup:
        xml.http('auto-config': 'true', 'use-expressions': 'true') {
            interceptUrl('/secure*', "hasAnyRole('ROLE_A','ROLE_C')")
            interceptUrl('/**', 'permitAll')
        }
        createAppContext()

        def fis = getFilter(FilterSecurityInterceptor)
        def fids = fis.getSecurityMetadataSource()
        Collection attrs = fids.getAttributes(createFilterinvocation("/secure", null));
        assert 1 == attrs.size()

        when: "Unprotected URL"
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("joe", "", "ROLE_A"));
        fis.invoke(createFilterinvocation("/permitallurl", null));
        then:
        notThrown(AccessDeniedException)

        when: "Invoking secure Url as a valid user"
        fis.invoke(createFilterinvocation("/secure", null));
        then:
        notThrown(AccessDeniedException)

        when: "User does not have the required role"
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("joe", "", "ROLE_B"));
        fis.invoke(createFilterinvocation("/secure", null));
        then:
        thrown(AccessDeniedException)
    }

    def disablingUrlRewritingThroughTheNamespaceSetsCorrectPropertyOnContextRepo() {
        xml.http('auto-config': 'true', 'disable-url-rewriting': 'true')
        createAppContext()

        expect:
        getFilter(SecurityContextPersistenceFilter).repo.disableUrlRewriting == true
    }

    def userDetailsServiceInParentContextIsLocatedSuccessfully() {
        when:
        createAppContext()
        httpAutoConfig {
            'remember-me'
        }
        appContext = new InMemoryXmlApplicationContext(writer.toString(), appContext)

        then:
        notThrown(BeansException)
    }

    def httpConfigWithNoAuthProvidersWorksOk() {
        when: "Http config has no internal authentication providers"
        xml.http() {
            'form-login'()
            anonymous(enabled: 'false')
        }
        createAppContext()
        FilterChainProxy fcp = appContext.getBean(BeanIds.FILTER_CHAIN_PROXY);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/j_spring_security_check");
        request.setServletPath("/j_spring_security_check");
        request.addParameter("j_username", "bob");
        request.addParameter("j_password", "bob");
        then: "App context creation and login request succeed"
        fcp.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
    }
}

class MockEntryPoint extends LoginUrlAuthenticationEntryPoint {
    public MockEntryPoint() {
        super.setLoginFormUrl("/notused");
    }
}
