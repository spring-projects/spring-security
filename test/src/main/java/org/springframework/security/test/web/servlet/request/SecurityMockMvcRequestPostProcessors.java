/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.test.web.servlet.request;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.web.support.WebTestUtils;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.util.Assert;

/**
 * Contains {@link MockMvc} {@link RequestPostProcessor} implementations for
 * Spring Security.
 *
 * @author Rob Winch
 * @since 4.0
 */
public final class SecurityMockMvcRequestPostProcessors {

    /**
     * Creates a {@link RequestPostProcessor} that will automatically populate a
     * valid {@link CsrfToken} in the request.
     *
     * @return the {@link CsrfRequestPostProcessor} for further customizations.
     */
    public static CsrfRequestPostProcessor csrf() {
        return new CsrfRequestPostProcessor();
    }

    /**
     * Creates a {@link RequestPostProcessor} that can be used to ensure that
     * the resulting request is ran with the user in the
     * {@link TestSecurityContextHolder}.
     *
     * @return the {@link RequestPostProcessor} to sue
     */
    public static RequestPostProcessor testSecurityContext() {
        return new TestSecurityContextHolderPostProcessor();
    }

    /**
     * Establish a {@link SecurityContext} that has a
     * {@link UsernamePasswordAuthenticationToken} for the
     * {@link Authentication#getPrincipal()} and a {@link User} for the
     * {@link UsernamePasswordAuthenticationToken#getPrincipal()}. All details
     * are declarative and do not require that the user actually exists.
     *
     * @param username
     *            the username to populate
     * @return the {@link UserRequestPostProcessor} for additional customization
     */
    public static UserRequestPostProcessor user(String username) {
        return new UserRequestPostProcessor(username);
    }

    /**
     * Establish a {@link SecurityContext} that has a
     * {@link UsernamePasswordAuthenticationToken} for the
     * {@link Authentication#getPrincipal()} and a custom {@link UserDetails}
     * for the {@link UsernamePasswordAuthenticationToken#getPrincipal()}. All
     * details are declarative and do not require that the user actually exists.
     *
     * @param user
     *            the UserDetails to populate
     * @return the {@link RequestPostProcessor} to use
     */
    public static RequestPostProcessor user(UserDetails user) {
        return new UserDetailsRequestPostProcessor(user);
    }

    /**
     * Establish a {@link SecurityContext} that uses the specified {@link Authentication} for the
     * {@link Authentication#getPrincipal()} and a custom {@link UserDetails}. All
     * details are declarative and do not require that the user actually exists.
     *
     * @param user
     *            the UserDetails to populate
     * @return the {@link RequestPostProcessor} to use
     */
    public static RequestPostProcessor authentication(
            Authentication authentication) {
        return new AuthenticationRequestPostProcessor(authentication);
    }

    /**
     * Establish the specified {@link SecurityContext} to be used.
     */
    public static RequestPostProcessor securityContext(
            SecurityContext securityContext) {
        return new SecurityContextRequestPostProcessor(securityContext);
    }

    /**
     * Convenience mechanism for setting the Authorization header to use HTTP
     * Basic with the given username and password. This method will
     * automatically perform the necessary Base64 encoding.
     *
     * @param username
     *            the username to include in the Authorization header.
     * @param password the password to include in the Authorization header.
     * @return the {@link RequestPostProcessor} to use
     */
    public static RequestPostProcessor httpBasic(String username, String password) {
        return new HttpBasicRequestPostProcessor(username, password);
    }

    /**
     * Populates a valid {@link CsrfToken} into the request.
     *
     * @author Rob Winch
     * @since 4.0
     */
    public static class CsrfRequestPostProcessor implements
            RequestPostProcessor {

        private boolean asHeader;

        private boolean useInvalidToken;

        /*
         * (non-Javadoc)
         *
         * @see
         * org.springframework.test.web.servlet.request.RequestPostProcessor
         * #postProcessRequest
         * (org.springframework.mock.web.MockHttpServletRequest)
         */
        public MockHttpServletRequest postProcessRequest(
                MockHttpServletRequest request) {

            CsrfTokenRepository repository = WebTestUtils
                    .getCsrfTokenRepository(request);
            CsrfToken token = repository.generateToken(request);
            repository.saveToken(token, request, new MockHttpServletResponse());
            String tokenValue = useInvalidToken ? "invalid" + token.getToken() : token.getToken();
            if(asHeader) {
                request.addHeader(token.getHeaderName(), tokenValue);
            } else {
                request.setParameter(token.getParameterName(), tokenValue);
            }
            return request;
        }

        /**
         * Instead of using the {@link CsrfToken} as a request parameter
         * (default) will populate the {@link CsrfToken} as a header.
         *
         * @return the {@link CsrfRequestPostProcessor} for additional customizations
         */
        public CsrfRequestPostProcessor asHeader() {
            this.asHeader = true;
            return this;
        }

        /**
         * Populates an invalid token value on the request.
         *
         * @return the {@link CsrfRequestPostProcessor} for additional customizations
         */
        public CsrfRequestPostProcessor useInvalidToken() {
            this.useInvalidToken = true;
            return this;
        }

        private CsrfRequestPostProcessor() {}
    }

    /**
     * Support class for {@link RequestPostProcessor}'s that establish a Spring
     * Security context
     */
    private static abstract class SecurityContextRequestPostProcessorSupport {

        /**
         * Saves the specified {@link Authentication} into an empty
         * {@link SecurityContext} using the {@link SecurityContextRepository}.
         *
         * @param authentication the {@link Authentication} to save
         * @param request the {@link HttpServletRequest} to use
         */
        final void save(Authentication authentication,
                HttpServletRequest request) {
            SecurityContext securityContext = SecurityContextHolder
                    .createEmptyContext();
            securityContext.setAuthentication(authentication);
            save(securityContext, request);
        }

        /**
         * Saves the {@link SecurityContext} using the
         * {@link SecurityContextRepository}
         *
         * @param securityContext the {@link SecurityContext} to save
         * @param request the {@link HttpServletRequest} to use
         */
        final void save(SecurityContext securityContext,
                HttpServletRequest request) {
            HttpServletResponse response = new MockHttpServletResponse();

            HttpRequestResponseHolder requestResponseHolder = new HttpRequestResponseHolder(
                    request, response);
            SecurityContextRepository securityContextRepository = WebTestUtils
                    .getSecurityContextRepository(request);
            securityContextRepository.loadContext(requestResponseHolder);

            request = requestResponseHolder.getRequest();
            response = requestResponseHolder.getResponse();

            securityContextRepository.saveContext(securityContext, request,
                    response);
        }
    }

    /**
     * Associates the {@link SecurityContext} found in
     * {@link TestSecurityContextHolder#getContext()} with the
     * {@link MockHttpServletRequest}.
     *
     * @author Rob Winch
     * @since 4.0
     */
    private final static class TestSecurityContextHolderPostProcessor extends
            SecurityContextRequestPostProcessorSupport implements
            RequestPostProcessor {

        public MockHttpServletRequest postProcessRequest(
                MockHttpServletRequest request) {
            save(TestSecurityContextHolder.getContext(), request);
            return request;
        }
    }

    /**
     * Associates the specified {@link SecurityContext} with the
     * {@link MockHttpServletRequest}.
     *
     * @author Rob Winch
     * @since 4.0
     */
    private final static class SecurityContextRequestPostProcessor extends
            SecurityContextRequestPostProcessorSupport implements
            RequestPostProcessor {

        private final SecurityContext securityContext;

        private SecurityContextRequestPostProcessor(
                SecurityContext securityContext) {
            this.securityContext = securityContext;
        }

        public MockHttpServletRequest postProcessRequest(
                MockHttpServletRequest request) {
            save(this.securityContext, request);
            return request;
        }
    }

    /**
     * Sets the specified {@link Authentication} on an empty
     * {@link SecurityContext} and associates it to the
     * {@link MockHttpServletRequest}
     *
     * @author Rob Winch
     * @since 4.0
     *
     */
    private final static class AuthenticationRequestPostProcessor extends
            SecurityContextRequestPostProcessorSupport implements
            RequestPostProcessor {
        private final Authentication authentication;

        private AuthenticationRequestPostProcessor(Authentication authentication) {
            this.authentication = authentication;
        }

        public MockHttpServletRequest postProcessRequest(
                MockHttpServletRequest request) {
            SecurityContext context = SecurityContextHolder.getContext();
            context.setAuthentication(authentication);
            save(authentication, request);
            return request;
        }
    }

    /**
     * Creates a {@link UsernamePasswordAuthenticationToken} and sets the
     * {@link UserDetails} as the principal and associates it to the
     * {@link MockHttpServletRequest}.
     *
     * @author Rob Winch
     * @since 4.0
     */
    private final static class UserDetailsRequestPostProcessor implements
            RequestPostProcessor {
        private final RequestPostProcessor delegate;

        public UserDetailsRequestPostProcessor(UserDetails user) {
            Authentication token = new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());

            delegate = new AuthenticationRequestPostProcessor(token);
        }

        public MockHttpServletRequest postProcessRequest(
                MockHttpServletRequest request) {
            return delegate.postProcessRequest(request);
        }
    }

    /**
     * Creates a {@link UsernamePasswordAuthenticationToken} and sets the
     * principal to be a {@link User} and associates it to the
     * {@link MockHttpServletRequest}.
     *
     * @author Rob Winch
     * @since 4.0
     */
    public final static class UserRequestPostProcessor extends
            SecurityContextRequestPostProcessorSupport implements
            RequestPostProcessor {

        private String username;

        private String password = "password";

        private static final String ROLE_PREFIX = "ROLE_";

        private Collection<? extends GrantedAuthority> authorities = AuthorityUtils
                .createAuthorityList("ROLE_USER");

        private boolean enabled = true;

        private boolean accountNonExpired = true;

        private boolean credentialsNonExpired = true;

        private boolean accountNonLocked = true;

        /**
         * Creates a new instance with the given username
         * @param username the username to use
         */
        private UserRequestPostProcessor(String username) {
            Assert.notNull(username, "username cannot be null");
            this.username = username;
        }

        /**
         * Specify the roles of the user to authenticate as. This method is
         * similar to {@link #authorities(GrantedAuthority...)}, but just not as
         * flexible.
         *
         * @param roles
         *            The roles to populate. Note that if the role does not
         *            start with {@link #rolePrefix(String)} it will
         *            automatically be prepended. This means by default
         *            {@code roles("ROLE_USER")} and {@code roles("USER")} are
         *            equivalent.
         * @see #authorities(GrantedAuthority...)
         * @see #rolePrefix(String)
         * @return the UserRequestPostProcessor for further customizations
         */
        public UserRequestPostProcessor roles(String... roles) {
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>(
                    roles.length);
            for (String role : roles) {
                if (role.startsWith(ROLE_PREFIX)) {
                    throw new IllegalArgumentException("Role should not start with "+ROLE_PREFIX + " since this method automatically prefixes with this value. Got "+ role);
                } else {
                    authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX
                            + role));
                }
            }
            this.authorities = authorities;
            return this;
        }

        /**
         * Populates the user's {@link GrantedAuthority}'s. The default is
         * ROLE_USER.
         *
         * @param authorities
         * @see #roles(String...)
         * @return the UserRequestPostProcessor for further customizations
         */
        public UserRequestPostProcessor authorities(
                GrantedAuthority... authorities) {
            return authorities(Arrays.asList(authorities));
        }

        /**
         * Populates the user's {@link GrantedAuthority}'s. The default is
         * ROLE_USER.
         *
         * @param authorities
         * @see #roles(String...)
         * @return the UserRequestPostProcessor for further customizations
         */
        public UserRequestPostProcessor authorities(
                Collection<? extends GrantedAuthority> authorities) {
            this.authorities = authorities;
            return this;
        }

        /**
         * Populates the user's password. The default is "password"
         *
         * @param password
         *            the user's password
         * @return the UserRequestPostProcessor for further customizations
         */
        public UserRequestPostProcessor password(String password) {
            this.password = password;
            return this;
        }

        public MockHttpServletRequest postProcessRequest(
                MockHttpServletRequest request) {
            UserDetailsRequestPostProcessor delegate = new UserDetailsRequestPostProcessor(createUser());
            return delegate.postProcessRequest(request);
        }

        /**
         * Creates a new {@link User}
         * @return the {@link User} for the principal
         */
        private User createUser() {
            return new User(username, password, enabled, accountNonExpired,
                    credentialsNonExpired, accountNonLocked, authorities);
        }
    }

    private static class HttpBasicRequestPostProcessor implements RequestPostProcessor {
        private String headerValue;

        private HttpBasicRequestPostProcessor(String username, String password) {
            byte[] toEncode;
            try {
                toEncode = (username + ":" + password).getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
            this.headerValue = "Basic " + new String(Base64.encode(toEncode));
        }

        public MockHttpServletRequest postProcessRequest(
                MockHttpServletRequest request) {
            request.addHeader("Authorization", headerValue);
            return request;
        }
    }

    private SecurityMockMvcRequestPostProcessors() { }
}