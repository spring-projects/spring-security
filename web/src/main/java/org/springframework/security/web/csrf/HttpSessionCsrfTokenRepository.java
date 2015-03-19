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

import java.util.UUID;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.util.Assert;
import org.springframework.web.util.WebUtils;

/**
 * A {@link CsrfTokenRepository} that stores the {@link CsrfToken} in the {@link HttpSession}.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class HttpSessionCsrfTokenRepository implements CsrfTokenRepository {
    private static final String DEFAULT_CSRF_PARAMETER_NAME = "_csrf";

    private static final String DEFAULT_CSRF_HEADER_NAME = "X-CSRF-TOKEN";

    private static final String DEFAULT_CSRF_TOKEN_ATTR_NAME = HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN");

    private String parameterName = DEFAULT_CSRF_PARAMETER_NAME;

    private String headerName = DEFAULT_CSRF_HEADER_NAME;

    private String cookieName;

    private String cookiePath;

    private String sessionAttributeName = DEFAULT_CSRF_TOKEN_ATTR_NAME;

    /*
     * (non-Javadoc)
     * @see org.springframework.security.web.csrf.CsrfTokenRepository#saveToken(org.springframework.security.web.csrf.CsrfToken, javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    public void saveToken(CsrfToken token, HttpServletRequest request,
            HttpServletResponse response) {
        if (token == null) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute(sessionAttributeName);
            }
        } else {
            HttpSession session = request.getSession();
            session.setAttribute(sessionAttributeName, token);
        }
        if (cookieName!=null) {
        	Cookie cookie = WebUtils.getCookie(request, cookieName);
			String value = token.getToken();
			if (cookie==null || token!=null && !value.equals(cookie.getValue())) {
				cookie = new Cookie(cookieName, value);
				if (cookiePath==null) {
					String path = request.getContextPath();
					cookie.setPath(path.equals("") ? "/" : path);
				} else {
					cookie.setPath(cookiePath);
				}
				response.addCookie(cookie);
			}
        }
    }

    /* (non-Javadoc)
     * @see org.springframework.security.web.csrf.CsrfTokenRepository#loadToken(javax.servlet.http.HttpServletRequest)
     */
    public CsrfToken loadToken(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        return (CsrfToken) session.getAttribute(sessionAttributeName);
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.web.csrf.CsrfTokenRepository#generateToken(javax.servlet.http.HttpServletRequest)
     */
    public CsrfToken generateToken(HttpServletRequest request) {
        return new DefaultCsrfToken(headerName, parameterName, createNewToken());
    }

    /**
     * Sets the {@link HttpServletRequest} parameter name that the {@link CsrfToken} is expected to appear on
     * @param parameterName the new parameter name to use
     */
    public void setParameterName(String parameterName) {
        Assert.hasLength(parameterName, "parameterName cannot be null or empty");
        this.parameterName = parameterName;
    }

    /**
     * Sets the header name that the {@link CsrfToken} is expected to appear on
     * and the header that the response will contain the {@link CsrfToken}.
     *
     * @param headerName
     *            the new header name to use
     */
    public void setHeaderName(String headerName) {
        Assert.hasLength(headerName, "headerName cannot be null or empty");
        this.headerName = headerName;
    }


    /**
     * The name of a cookie to send containing the CSRF token value. Some client-side
     * frameworks use this mechanism to find the value of the token, and then send it
     * back as a header if it is set.
     * 
	 * @param cookieName the cookie name to set (default null, meaning not to send
	 * a cookie at all)
	 */
	public void setCookieName(String cookieName) {
		this.cookieName = cookieName;
	}
	
	/**
	 * The path to send in a cookie (if {@link #setCookieName(String) cookieName} is set). 
	 * If unset the path will be set to the context path of the request.
	 *  
	 * @param cookiePath the cookie path to set (e.g. "/"), default null.
	 */
	public void setCookiePath(String cookiePath) {
		this.cookiePath = cookiePath;
	}

    /**
     * Sets the {@link HttpSession} attribute name that the {@link CsrfToken} is stored in
     * @param sessionAttributeName the new attribute name to use
     */
    public void setSessionAttributeName(String sessionAttributeName) {
        Assert.hasLength(sessionAttributeName, "sessionAttributename cannot be null or empty");
        this.sessionAttributeName = sessionAttributeName;
    }

    private String createNewToken() {
        return UUID.randomUUID().toString();
    }
}
