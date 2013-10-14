/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.web.csrf;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * <p>
 * Applies <a
 * href="https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)"
 * >CSRF</a> protection using a synchronizer token pattern. Developers are
 * required to ensure that {@link CsrfFilter} is invoked for any request that
 * allows state to change. Typically this just means that they should ensure
 * their web application follows proper REST semantics (i.e. do not change state
 * with the HTTP methods GET, HEAD, TRACE, OPTIONS).
 * </p>
 *
 * <p>
 * Typically the {@link CsrfTokenRepository} implementation chooses to store the
 * {@link CsrfToken} in {@link HttpSession} with
 * {@link HttpSessionCsrfTokenRepository}. This is preferred to storing the
 * token in a cookie which.
 * </p>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class CsrfFilter extends OncePerRequestFilter {
    private final Log logger = LogFactory.getLog(getClass());
    private final CsrfTokenRepository tokenRepository;
    private RequestMatcher requireCsrfProtectionMatcher = new DefaultRequiresCsrfMatcher();
    private AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();

    public CsrfFilter(CsrfTokenRepository csrfTokenRepository) {
        Assert.notNull(csrfTokenRepository, "csrfTokenRepository cannot be null");
        this.tokenRepository = csrfTokenRepository;
    }

    /* (non-Javadoc)
     * @see org.springframework.web.filter.OncePerRequestFilter#doFilterInternal(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain)
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        CsrfToken csrfToken = tokenRepository.loadToken(request);
        if(csrfToken == null) {
            CsrfToken generatedToken = tokenRepository.generateToken(request);
            csrfToken = new SaveOnAccessCsrfToken(tokenRepository, request, response, generatedToken);
        }
        request.setAttribute(CsrfToken.class.getName(), csrfToken);
        request.setAttribute(csrfToken.getParameterName(), csrfToken);

        if(!requireCsrfProtectionMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String actualToken = request.getHeader(csrfToken.getHeaderName());
        if(actualToken == null) {
            actualToken = request.getParameter(csrfToken.getParameterName());
        }
        if(!csrfToken.getToken().equals(actualToken)) {
            if(logger.isDebugEnabled()) {
                logger.debug("Invalid CSRF token found for " + UrlUtils.buildFullRequestUrl(request));
            }
            accessDeniedHandler.handle(request, response, new InvalidCsrfTokenException(csrfToken, actualToken));
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Specifies a {@link RequestMatcher} that is used to determine if CSRF
     * protection should be applied. If the {@link RequestMatcher} returns true
     * for a given request, then CSRF protection is applied.
     *
     * <p>
     * The default is to apply CSRF protection for any HTTP method other than
     * GET, HEAD, TRACE, OPTIONS.
     * </p>
     *
     * @param requireCsrfProtectionMatcher
     *            the {@link RequestMatcher} used to determine if CSRF
     *            protection should be applied.
     */
    public void setRequireCsrfProtectionMatcher(RequestMatcher requireCsrfProtectionMatcher) {
        Assert.notNull(requireCsrfProtectionMatcher, "requireCsrfProtectionMatcher cannot be null");
        this.requireCsrfProtectionMatcher = requireCsrfProtectionMatcher;
    }


    /**
     * Specifies a {@link AccessDeniedHandler} that should be used when CSRF protection fails.
     *
     * <p>
     * The default is to use AccessDeniedHandlerImpl with no arguments.
     * </p>
     *
     * @param accessDeniedHandler
     *            the {@link AccessDeniedHandler} to use
     */
    public void setAccessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
        Assert.notNull(accessDeniedHandler, "accessDeniedHandler cannot be null");
        this.accessDeniedHandler = accessDeniedHandler;
    }

    @SuppressWarnings("serial")
    private static final class SaveOnAccessCsrfToken implements CsrfToken {
        private transient CsrfTokenRepository tokenRepository;
        private transient HttpServletRequest request;
        private transient HttpServletResponse response;

        private final CsrfToken delegate;

        public SaveOnAccessCsrfToken(CsrfTokenRepository tokenRepository,
                HttpServletRequest request, HttpServletResponse response,
                CsrfToken delegate) {
            super();
            this.tokenRepository = tokenRepository;
            this.request = request;
            this.response = response;
            this.delegate = delegate;
        }

        public String getHeaderName() {
            return delegate.getHeaderName();
        }

        public String getParameterName() {
            return delegate.getParameterName();
        }

        public String getToken() {
            saveTokenIfNecessary();
            return delegate.getToken();
        }

        @Override
        public String toString() {
            return "SaveOnAccessCsrfToken [delegate=" + delegate + "]";
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result
                    + ((delegate == null) ? 0 : delegate.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            SaveOnAccessCsrfToken other = (SaveOnAccessCsrfToken) obj;
            if (delegate == null) {
                if (other.delegate != null)
                    return false;
            } else if (!delegate.equals(other.delegate))
                return false;
            return true;
        }

        private void saveTokenIfNecessary() {
            if(this.tokenRepository == null) {
                return;
            }

            synchronized(this) {
                if(tokenRepository != null) {
                    this.tokenRepository.saveToken(delegate, request, response);
                    this.tokenRepository = null;
                    this.request = null;
                    this.response = null;
                }
            }
        }

    }

    private static final class DefaultRequiresCsrfMatcher implements RequestMatcher {
        private Pattern allowedMethods = Pattern.compile("^(GET|HEAD|TRACE|OPTIONS)$");

        /* (non-Javadoc)
         * @see org.springframework.security.web.util.matcher.RequestMatcher#matches(javax.servlet.http.HttpServletRequest)
         */
        public boolean matches(HttpServletRequest request) {
            return !allowedMethods.matcher(request.getMethod()).matches();
        }
    }
}
