package org.springframework.security.ui.webapp;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.AuthenticationException;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.FilterChainOrder;
import org.springframework.security.ui.SpringSecurityFilter;
import org.springframework.security.ui.rememberme.AbstractRememberMeServices;

/**
 * For internal use with namespace configuration in the case where a user doesn't configure a login page.
 * The configuration code will insert this filter in the chain instead.
 *
 * Will only work if a redirect is used to the login page.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class DefaultLoginPageGeneratingFilter extends SpringSecurityFilter {
    public static final String DEFAULT_LOGIN_PAGE_URL = "/spring_security_login";
    public static final String ERROR_PARAMETER_NAME = "login_error";
    private String authenticationUrl;
    private String usernameParameter;
    private String passwordParameter;
    private String rememberMeParameter;

    public DefaultLoginPageGeneratingFilter(AuthenticationProcessingFilter authFilter) {
        authenticationUrl = authFilter.getDefaultFilterProcessesUrl();
        usernameParameter = authFilter.getUsernameParameter();
        passwordParameter = authFilter.getPasswordParameter();

        if (authFilter.getRememberMeServices() instanceof AbstractRememberMeServices) {
            rememberMeParameter = ((AbstractRememberMeServices)authFilter.getRememberMeServices()).getParameter();
        }
    }

    protected void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (isLoginUrlRequest(request)) {
            response.getOutputStream().print(generateLoginPageHtml(request));

            return;
        }

        chain.doFilter(request, response);
    }

    private String generateLoginPageHtml(HttpServletRequest request) {
        boolean loginError = request.getParameter(ERROR_PARAMETER_NAME) != null;
        String errorMsg = "none";
        String lastUser = "";

        if (loginError) {
            HttpSession session = request.getSession(false);

            if(session != null) {
            	lastUser = (String) session.getAttribute(AuthenticationProcessingFilter.SPRING_SECURITY_LAST_USERNAME_KEY);
            	AuthenticationException ex = (AuthenticationException) session.getAttribute(AbstractProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY);
                errorMsg = ex != null ? ex.getMessage() : "none";
                if (lastUser == null) {
                	lastUser = "";
                }
            }
        }

        return "<html><head><title>Login Page</title></head><body onload='document.f.j_username.focus();'>\n" +
                (loginError ? ("<font color='red'>Your login attempt was not successful, try again.<br/><br/>Reason: " +
                        errorMsg + "</font>") : "") +
                " <form name='f' action='" + request.getContextPath() + authenticationUrl + "' method='POST'>\n" +
                "   <table>\n" +
                "     <tr><td>User:</td><td><input type='text' name='" + usernameParameter + "'  value='" + lastUser +
                "'></td></tr>\n" +
                "     <tr><td>Password:</td><td><input type='password' name='"+ passwordParameter +"'></td></tr>\n" +

                (rememberMeParameter == null ? "" :
                "     <tr><td><input type='checkbox' name='"+ rememberMeParameter +
                        "'></td><td>Remember me on this computer.</td></tr>\n"
                ) +
                "     <tr><td colspan='2'><input name=\"submit\" type=\"submit\"></td></tr>\n" +
                "     <tr><td colspan='2'><input name=\"reset\" type=\"reset\"></td></tr>\n" +
                "   </table>\n" +
                " </form></body></html>";
    }

    public int getOrder() {
        return FilterChainOrder.LOGIN_PAGE_FILTER;
    }

	private boolean isLoginUrlRequest(HttpServletRequest request) {
		String uri = request.getRequestURI();
		int pathParamIndex = uri.indexOf(';');

		if (pathParamIndex > 0) {
			// strip everything after the first semi-colon
			uri = uri.substring(0, pathParamIndex);
		}

		if ("".equals(request.getContextPath())) {
			return uri.endsWith(DEFAULT_LOGIN_PAGE_URL);
		}

		return uri.endsWith(request.getContextPath() + DEFAULT_LOGIN_PAGE_URL);
	}
}
