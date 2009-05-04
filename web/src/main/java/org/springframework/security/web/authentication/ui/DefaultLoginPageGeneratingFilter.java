package org.springframework.security.web.authentication.ui;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.BeanWrapperImpl;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.FilterChainOrder;
import org.springframework.security.web.SpringSecurityFilter;
import org.springframework.security.web.authentication.AbstractProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationProcessingFilter;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;

/**
 * For internal use with namespace configuration in the case where a user doesn't configure a login page.
 * The configuration code will insert this filter in the chain instead.
 *
 * Will only work if a redirect is used to the login page.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class DefaultLoginPageGeneratingFilter extends SpringSecurityFilter {
    public static final String DEFAULT_LOGIN_PAGE_URL = "/spring_security_login";
    public static final String ERROR_PARAMETER_NAME = "login_error";
    boolean formLoginEnabled;
    boolean openIdEnabled;
    private String authenticationUrl;
    private String usernameParameter;
    private String passwordParameter;
    private String rememberMeParameter;
    private String openIDauthenticationUrl;
    private String openIDusernameParameter;
    private String openIDrememberMeParameter;

    public DefaultLoginPageGeneratingFilter(AbstractProcessingFilter filter) {
        if (filter instanceof AuthenticationProcessingFilter) {
            init((AuthenticationProcessingFilter)filter, null);
        } else {
            init(null, filter);
        }
    }

    public DefaultLoginPageGeneratingFilter(AuthenticationProcessingFilter authFilter, AbstractProcessingFilter openIDFilter) {
        init(authFilter, openIDFilter);
    }

    private void init(AuthenticationProcessingFilter authFilter, AbstractProcessingFilter openIDFilter) {
        if (authFilter != null) {
            formLoginEnabled = true;
            authenticationUrl = authFilter.getFilterProcessesUrl();
            usernameParameter = authFilter.getUsernameParameter();
            passwordParameter = authFilter.getPasswordParameter();

            if (authFilter.getRememberMeServices() instanceof AbstractRememberMeServices) {
                rememberMeParameter = ((AbstractRememberMeServices)authFilter.getRememberMeServices()).getParameter();
            }
        }

        if (openIDFilter != null) {
            openIdEnabled = true;
            openIDauthenticationUrl = openIDFilter.getFilterProcessesUrl();
            openIDusernameParameter = (String) (new BeanWrapperImpl(openIDFilter)).getPropertyValue("claimedIdentityFieldName");

            if (openIDFilter.getRememberMeServices() instanceof AbstractRememberMeServices) {
                openIDrememberMeParameter = ((AbstractRememberMeServices)openIDFilter.getRememberMeServices()).getParameter();
            }
        }
    }

    protected void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (isLoginUrlRequest(request)) {
            String loginPageHtml = generateLoginPageHtml(request);
            response.setContentType("text/html;charset=UTF-8");
            response.setContentLength(loginPageHtml.length());
            response.getWriter().write(loginPageHtml);

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

        StringBuffer sb = new StringBuffer();

        sb.append("<html><head><title>Login Page</title></head>");

        if (formLoginEnabled) {
            sb.append("<body onload='document.f.").append(usernameParameter).append(".focus();'>\n");
        }

        if (loginError) {
            sb.append("<p><font color='red'>Your login attempt was not successful, try again.<br/><br/>Reason: ");
            sb.append(errorMsg);
            sb.append("</font></p>");
        }

        if (formLoginEnabled) {
            sb.append("<h3>Login with Username and Password</h3>");
            sb.append("<form name='f' action='").append(request.getContextPath()).append(authenticationUrl).append("' method='POST'>\n");
            sb.append(" <table>\n");
            sb.append("    <tr><td>User:</td><td><input type='text' name='");
            sb.append(usernameParameter).append("' value='").append(lastUser).append("'></td></tr>\n");
            sb.append("    <tr><td>Password:</td><td><input type='password' name='").append(passwordParameter).append("'/></td></tr>\n");

            if (rememberMeParameter != null) {
                sb.append("    <tr><td><input type='checkbox' name='").append(rememberMeParameter).append("'/></td><td>Remember me on this computer.</td></tr>\n");
            }

            sb.append("    <tr><td colspan='2'><input name=\"submit\" type=\"submit\"/></td></tr>\n");
            sb.append("    <tr><td colspan='2'><input name=\"reset\" type=\"reset\"/></td></tr>\n");
            sb.append("  </table>\n");
            sb.append("</form>");
        }

        if(openIdEnabled) {
            sb.append("<h3>Login with OpenID Identity</h3>");
            sb.append("<form name='oidf' action='").append(request.getContextPath()).append(openIDauthenticationUrl).append("' method='POST'>\n");
            sb.append(" <table>\n");
            sb.append("    <tr><td>Identity:</td><td><input type='text' name='");
            sb.append(openIDusernameParameter).append("'/></td></tr>\n");

            if (rememberMeParameter != null) {
                sb.append("    <tr><td><input type='checkbox' name='").append(openIDrememberMeParameter).append("'></td><td>Remember me on this computer.</td></tr>\n");
            }

            sb.append("    <tr><td colspan='2'><input name=\"submit\" type=\"submit\"/></td></tr>\n");
            sb.append("    <tr><td colspan='2'><input name=\"reset\" type=\"reset\"/></td></tr>\n");
            sb.append("  </table>\n");
            sb.append("</form>");
        }

        sb.append("</body></html>");

        return sb.toString();
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
