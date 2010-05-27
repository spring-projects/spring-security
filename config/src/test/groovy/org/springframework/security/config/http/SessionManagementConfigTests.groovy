package org.springframework.security.config.http

import static org.junit.Assert.*;

import groovy.lang.Closure;

import javax.servlet.Filter;
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;

import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.BeanIds
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.session.SessionRegistryImpl
import org.springframework.security.util.FieldUtils
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.context.NullSecurityContextRepository
import org.springframework.security.web.context.SaveContextOnUpdateOrErrorResponseWrapper
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter
import org.springframework.security.web.session.ConcurrentSessionFilter
import org.springframework.security.web.session.SessionManagementFilter


/**
 * Tests session-related functionality for the &lt;http&gt; namespace element and &lt;session-management&gt;
 *
 * @author Luke Taylor
 */
class SessionManagementConfigTests extends AbstractHttpConfigTests {

    def settingCreateSessionToAlwaysSetsFilterPropertiesCorrectly() {
        httpCreateSession('always') { }
        createAppContext();

        def filter = getFilter(SecurityContextPersistenceFilter.class);

        expect:
        filter.forceEagerSessionCreation == true
        filter.repo.allowSessionCreation == true
        filter.repo.disableUrlRewriting == false
    }

    def settingCreateSessionToNeverSetsFilterPropertiesCorrectly() {
        httpCreateSession('never') { }
        createAppContext();

        def filter = getFilter(SecurityContextPersistenceFilter.class);

        expect:
        filter.forceEagerSessionCreation == false
        filter.repo.allowSessionCreation == false
    }

    def settingCreateSessionToStatelessSetsFilterPropertiesCorrectly() {
        httpCreateSession('stateless') { }
        createAppContext();

        def filter = getFilter(SecurityContextPersistenceFilter.class);

        expect:
        filter.forceEagerSessionCreation == false
        filter.repo instanceof NullSecurityContextRepository
        getFilter(SessionManagementFilter.class) == null
        getFilter(RequestCacheAwareFilter.class) == null
    }

    def settingCreateSessionToIfRequiredDoesntCreateASessionForPublicInvocation() {
        httpCreateSession('ifRequired') { }
        createAppContext();

        def filter = getFilter(SecurityContextPersistenceFilter.class);

        expect:
        filter.forceEagerSessionCreation == false
        filter.repo.allowSessionCreation == true
    }

    def httpCreateSession(String create, Closure c) {
        xml.http(['auto-config': 'true', 'create-session': create], c)
    }

    def concurrentSessionSupportAddsFilterAndExpectedBeans() {
        httpAutoConfig {
            'session-management'() {
                'concurrency-control'('session-registry-alias':'sr', 'expired-url': '/expired')
            }
        }
        createAppContext();
        List filters = getFilters("/someurl");

        expect:
        filters.get(0) instanceof ConcurrentSessionFilter
        appContext.getBean("sr") != null
        getFilter(SessionManagementFilter.class) != null
        sessionRegistryIsValid();
    }

    def externalSessionStrategyIsSupported() {
        when:
        httpAutoConfig {
            'session-management'('session-authentication-strategy-ref':'ss')
        }
        bean('ss', SessionFixationProtectionStrategy.class.name)
        createAppContext();

        then:
        notThrown(Exception.class)
    }

    def externalSessionRegistryBeanIsConfiguredCorrectly() {
        httpAutoConfig {
            'session-management'() {
                'concurrency-control'('session-registry-ref':'sr')
            }
        }
        bean('sr', SessionRegistryImpl.class.name)
        createAppContext();

        expect:
        sessionRegistryIsValid();
    }

    def sessionRegistryIsValid() {
        Object sessionRegistry = appContext.getBean("sr");
        Object sessionRegistryFromConcurrencyFilter = FieldUtils.getFieldValue(
                getFilter(ConcurrentSessionFilter.class), "sessionRegistry");
        Object sessionRegistryFromFormLoginFilter = FieldUtils.getFieldValue(
                getFilter(UsernamePasswordAuthenticationFilter.class),"sessionStrategy.sessionRegistry");
        Object sessionRegistryFromMgmtFilter = FieldUtils.getFieldValue(
                getFilter(SessionManagementFilter.class),"sessionStrategy.sessionRegistry");

        assertSame(sessionRegistry, sessionRegistryFromConcurrencyFilter);
        assertSame(sessionRegistry, sessionRegistryFromMgmtFilter);
        // SEC-1143
        assertSame(sessionRegistry, sessionRegistryFromFormLoginFilter);
        true;
    }

    def concurrentSessionMaxSessionsIsCorrectlyConfigured() {
        setup:
        httpAutoConfig {
            'session-management'('session-authentication-error-url':'/max-exceeded') {
                'concurrency-control'('max-sessions': '2', 'error-if-maximum-exceeded':'true')
            }
        }
        createAppContext();

        def seshFilter = getFilter(SessionManagementFilter.class);
        def auth = new UsernamePasswordAuthenticationToken("bob", "pass");
        SecurityContextHolder.getContext().setAuthentication(auth);
        MockHttpServletResponse mockResponse = new MockHttpServletResponse();
        def response = new SaveContextOnUpdateOrErrorResponseWrapper(mockResponse, false) {
            protected void saveContext(SecurityContext context) {
            }
        };
        when: "First session is established"
        seshFilter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());
        then: "ok"
        mockResponse.redirectedUrl == null
        when: "Second session is established"
        seshFilter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());
        then: "ok"
        mockResponse.redirectedUrl == null
        when: "Third session is established"
        seshFilter.doFilter(new MockHttpServletRequest(), response, new MockFilterChain());
        then: "Rejected"
        mockResponse.redirectedUrl == "/max-exceeded";
    }

    def disablingSessionProtectionRemovesSessionManagementFilterIfNoInvalidSessionUrlSet() {
        httpAutoConfig {
            'session-management'('session-fixation-protection': 'none')
        }
        createAppContext()

        expect:
        !(getFilters("/someurl")[8] instanceof SessionManagementFilter)
    }

    def disablingSessionProtectionRetainsSessionManagementFilterInvalidSessionUrlSet() {
        httpAutoConfig {
            'session-management'('session-fixation-protection': 'none', 'invalid-session-url': '/timeoutUrl')
        }
        createAppContext()
        def filter = getFilters("/someurl")[8]

        expect:
        filter instanceof SessionManagementFilter
        filter.invalidSessionUrl == '/timeoutUrl'
    }

}
