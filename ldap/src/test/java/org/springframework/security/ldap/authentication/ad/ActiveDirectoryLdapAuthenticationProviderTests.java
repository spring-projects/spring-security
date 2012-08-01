/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.ldap.authentication.ad;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider.ContextFactory;

import org.apache.directory.shared.ldap.util.EmptyEnumeration;
import org.hamcrest.BaseMatcher;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.*;
import org.junit.rules.ExpectedException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Name;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.*;

/**
 * @author Luke Taylor
 * @author Rob Winch
 */
public class ActiveDirectoryLdapAuthenticationProviderTests {
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    ActiveDirectoryLdapAuthenticationProvider provider;
    UsernamePasswordAuthenticationToken joe = new UsernamePasswordAuthenticationToken("joe", "password");

    @Before
    public void setUp() throws Exception {
        provider = new ActiveDirectoryLdapAuthenticationProvider("mydomain.eu", "ldap://192.168.1.200/");
    }

    @Test
    public void bindPrincipalIsCreatedCorrectly() throws Exception {
        assertEquals("joe@mydomain.eu", provider.createBindPrincipal("joe"));
        assertEquals("joe@mydomain.eu", provider.createBindPrincipal("joe@mydomain.eu"));
    }

    @Test
    public void successfulAuthenticationProducesExpectedAuthorities() throws Exception {
        DirContext ctx = mock(DirContext.class);
        when(ctx.getNameInNamespace()).thenReturn("");

        DirContextAdapter dca = new DirContextAdapter();
        SearchResult sr = new SearchResult("CN=Joe Jannsen,CN=Users", null, dca.getAttributes());
        when(ctx.search(any(Name.class), any(String.class), any(Object[].class), any(SearchControls.class)))
                .thenReturn(new MockNamingEnumeration(sr))
                .thenReturn(new MockNamingEnumeration(sr));

        provider.contextFactory = createContextFactoryReturning(ctx);

        Authentication result = provider.authenticate(joe);

        assertEquals(0, result.getAuthorities().size());

        dca.addAttributeValue("memberOf","CN=Admin,CN=Users,DC=mydomain,DC=eu");

        sr.setAttributes(dca.getAttributes());

        result = provider.authenticate(joe);

        assertEquals(1, result.getAuthorities().size());
    }

    @Test
    public void nullDomainIsSupportedIfAuthenticatingWithFullUserPrincipal() throws Exception {
        provider = new ActiveDirectoryLdapAuthenticationProvider(null, "ldap://192.168.1.200/");
        DirContext ctx = mock(DirContext.class);
        when(ctx.getNameInNamespace()).thenReturn("");

        DirContextAdapter dca = new DirContextAdapter();
        SearchResult sr = new SearchResult("CN=Joe Jannsen,CN=Users", null, dca.getAttributes());
        when(ctx.search(eq(new DistinguishedName("DC=mydomain,DC=eu")), any(String.class), any(Object[].class), any(SearchControls.class)))
                .thenReturn(new MockNamingEnumeration(sr));
        provider.contextFactory = createContextFactoryReturning(ctx);

        try {
            provider.authenticate(joe);
            fail("Expected BadCredentialsException for user with no domain information");
        } catch (BadCredentialsException expected) {
        }

        provider.authenticate(new UsernamePasswordAuthenticationToken("joe@mydomain.eu", "password"));
    }

    @Test(expected = BadCredentialsException.class)
    public void failedUserSearchCausesBadCredentials() throws Exception {
        DirContext ctx = mock(DirContext.class);
        when(ctx.getNameInNamespace()).thenReturn("");
        when(ctx.search(any(Name.class), any(String.class), any(Object[].class), any(SearchControls.class)))
                .thenThrow(new NameNotFoundException());

        provider.contextFactory = createContextFactoryReturning(ctx);

        provider.authenticate(joe);
    }

    // SEC-2017
    @Test(expected = BadCredentialsException.class)
    public void noUserSearchCausesUsernameNotFound() throws Exception {
        DirContext ctx = mock(DirContext.class);
        when(ctx.getNameInNamespace()).thenReturn("");
        when(ctx.search(any(Name.class), any(String.class), any(Object[].class), any(SearchControls.class)))
                .thenReturn(new EmptyEnumeration<SearchResult>());

        provider.contextFactory = createContextFactoryReturning(ctx);

        provider.authenticate(joe);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = IncorrectResultSizeDataAccessException.class)
    public void duplicateUserSearchCausesError() throws Exception {
        DirContext ctx = mock(DirContext.class);
        when(ctx.getNameInNamespace()).thenReturn("");
        NamingEnumeration<SearchResult> searchResults = mock(NamingEnumeration.class);
        when(searchResults.hasMore()).thenReturn(true,true,false);
        SearchResult searchResult = mock(SearchResult.class);
        when(searchResult.getName()).thenReturn("ou=1","ou=2");
        when(searchResults.next()).thenReturn(searchResult);
        when(ctx.search(any(Name.class), any(String.class), any(Object[].class), any(SearchControls.class)))
                .thenReturn(searchResults );

        provider.contextFactory = createContextFactoryReturning(ctx);

        provider.authenticate(joe);
    }

    static final String msg = "[LDAP: error code 49 - 80858585: LdapErr: DSID-DECAFF0, comment: AcceptSecurityContext error, data ";

    @Test(expected = BadCredentialsException.class)
    public void userNotFoundIsCorrectlyMapped() {
        provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "525, xxxx]"));
        provider.setConvertSubErrorCodesToExceptions(true);
        provider.authenticate(joe);
    }

    @Test(expected = BadCredentialsException.class)
    public void incorrectPasswordIsCorrectlyMapped() {
        provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "52e, xxxx]"));
        provider.setConvertSubErrorCodesToExceptions(true);
        provider.authenticate(joe);
    }

    @Test(expected = BadCredentialsException.class)
    public void notPermittedIsCorrectlyMapped() {
        provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "530, xxxx]"));
        provider.setConvertSubErrorCodesToExceptions(true);
        provider.authenticate(joe);
    }

    @Test
    public void passwordNeedsResetIsCorrectlyMapped() {
        final String dataCode = "773";
        provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + dataCode+", xxxx]"));
        provider.setConvertSubErrorCodesToExceptions(true);

        thrown.expect(BadCredentialsException.class);
        thrown.expect(new BaseMatcher<BadCredentialsException>() {
            private Matcher<Object> causeInstance = CoreMatchers.instanceOf(ActiveDirectoryAuthenticationException.class);
            private Matcher<String> causeDataCode = CoreMatchers.equalTo(dataCode);
            public boolean matches(Object that) {
                Throwable t = (Throwable) that;
                ActiveDirectoryAuthenticationException cause = (ActiveDirectoryAuthenticationException) t.getCause();
                return causeInstance.matches(cause) && causeDataCode.matches(cause.getDataCode());
            }

            public void describeTo(Description desc) {
                desc.appendText("getCause() ");
                causeInstance.describeTo(desc);
                desc.appendText("getCause().getDataCode() ");
                causeDataCode.describeTo(desc);
            }
        });

        provider.authenticate(joe);
    }

    @Test(expected = CredentialsExpiredException.class)
    public void expiredPasswordIsCorrectlyMapped() {
        provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "532, xxxx]"));

        try {
            provider.authenticate(joe);
            fail();
        } catch (BadCredentialsException expected) {
        }

        provider.setConvertSubErrorCodesToExceptions(true);
        provider.authenticate(joe);
    }

    @Test(expected = DisabledException.class)
    public void accountDisabledIsCorrectlyMapped() {
        provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "533, xxxx]"));
        provider.setConvertSubErrorCodesToExceptions(true);
        provider.authenticate(joe);
    }

    @Test(expected = AccountExpiredException.class)
    public void accountExpiredIsCorrectlyMapped() {
        provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "701, xxxx]"));
        provider.setConvertSubErrorCodesToExceptions(true);
        provider.authenticate(joe);
    }

    @Test(expected = LockedException.class)
    public void accountLockedIsCorrectlyMapped() {
        provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "775, xxxx]"));
        provider.setConvertSubErrorCodesToExceptions(true);
        provider.authenticate(joe);
    }

    @Test(expected = BadCredentialsException.class)
    public void unknownErrorCodeIsCorrectlyMapped() {
        provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "999, xxxx]"));
        provider.setConvertSubErrorCodesToExceptions(true);
        provider.authenticate(joe);
    }

    @Test(expected = BadCredentialsException.class)
    public void errorWithNoSubcodeIsHandledCleanly() throws Exception {
        provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg));
        provider.setConvertSubErrorCodesToExceptions(true);
        provider.authenticate(joe);
    }

    @Test(expected = org.springframework.ldap.CommunicationException.class)
    public void nonAuthenticationExceptionIsConvertedToSpringLdapException() throws Exception {
        provider.contextFactory = createContextFactoryThrowing(new CommunicationException(msg));
        provider.authenticate(joe);
    }

    ContextFactory createContextFactoryThrowing(final NamingException e) {
        return new ContextFactory() {
            @Override
            DirContext createContext(Hashtable<?, ?> env) throws NamingException {
                throw e;
            }
        };
    }


    ContextFactory createContextFactoryReturning(final DirContext ctx) {
        return new ContextFactory() {
            @Override
            DirContext createContext(Hashtable<?, ?> env) throws NamingException {
                return ctx;
            }
        };
    }

    static class MockNamingEnumeration implements NamingEnumeration<SearchResult> {
        private SearchResult sr;

        public MockNamingEnumeration(SearchResult sr) {
            this.sr = sr;
        }

        public SearchResult next() {
            SearchResult result = sr;
            sr = null;
            return result;
        }

        public boolean hasMore() {
            return sr != null;
        }

        public void close() {
        }

        public boolean hasMoreElements() {
            return hasMore();
        }

        public SearchResult nextElement() {
            return next();
        }
    }

//    @Test
//    public void realAuthenticationIsSucessful() throws Exception {
//        ActiveDirectoryLdapAuthenticationProvider provider =
//                new ActiveDirectoryLdapAuthenticationProvider(null, "ldap://192.168.1.200/");
//
//        provider.setConvertSubErrorCodesToExceptions(true);
//
//        Authentication result = provider.authenticate(new UsernamePasswordAuthenticationToken("luke@fenetres.monkeymachine.eu","p!ssw0rd"));
//
//        assertEquals(1, result.getAuthorities().size());
//        assertTrue(result.getAuthorities().contains(new SimpleGrantedAuthority("blah")));
//    }
}
