package org.springframework.security.ui.webapp;

import org.springframework.security.AuthenticationException;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.FilterChainOrderUtils;
import org.springframework.security.ui.SpringSecurityFilter;
import org.springframework.security.ui.rememberme.TokenBasedRememberMeServices;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

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
    public static final String DEFAULT_LOGIN_PAGE_URL = "/login";
    private String authenticationUrl;
    private String usernameParameter;
    private String passwordParameter;
    private String rememberMeParameter;

    public DefaultLoginPageGeneratingFilter(AuthenticationProcessingFilter authFilter) {
        authenticationUrl = authFilter.getDefaultFilterProcessesUrl();
        usernameParameter = authFilter.getUsernameParameter();
        passwordParameter = authFilter.getPasswordParameter();

        if (authFilter.getRememberMeServices() instanceof TokenBasedRememberMeServices) {
            rememberMeParameter = ((TokenBasedRememberMeServices)authFilter.getRememberMeServices()).getParameter();
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
        boolean loginError = StringUtils.hasText(request.getParameter("login_error"));
        String errorMsg = "none";
        String lastUser = "";

        if (loginError) {
            HttpSession session = request.getSession(false);

            if(session != null) {
                 errorMsg = ((AuthenticationException)
                        session.getAttribute(AbstractProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY)).getMessage();
            }
        }

        return "<html><head><title>Login Page</title></head><body>\n" +
                (loginError ? ("<font color='red'>Your login attempt was not successful, try again.<br/><br/>Reason: " +
                        errorMsg + "</font>") : "") +
                " <form action='" + request.getContextPath() + authenticationUrl + "' method='POST'>\n" +
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
        return FilterChainOrderUtils.LOGIN_PAGE_FILTER_ORDER;
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
