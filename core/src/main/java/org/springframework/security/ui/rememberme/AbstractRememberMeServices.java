package org.springframework.security.ui.rememberme;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.Authentication;
import org.springframework.security.SpringSecurityMessageSource;
import org.springframework.security.AccountStatusException;
import org.springframework.security.providers.rememberme.RememberMeAuthenticationToken;
import org.springframework.security.ui.AuthenticationDetailsSource;
import org.springframework.security.ui.WebAuthenticationDetailsSource;
import org.springframework.security.ui.logout.LogoutHandler;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.security.userdetails.UserDetailsChecker;
import org.springframework.security.userdetails.checker.AccountStatusUserDetailsChecker;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.ServletRequestUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Base class for RememberMeServices implementations.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public abstract class AbstractRememberMeServices implements RememberMeServices, InitializingBean, LogoutHandler {
	//~ Static fields/initializers =====================================================================================

    public static final String SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY = "SPRING_SECURITY_REMEMBER_ME_COOKIE";
    public static final String DEFAULT_PARAMETER = "_spring_security_remember_me";

    private static final String DELIMITER = ":";

	//~ Instance fields ================================================================================================
    protected final Log logger = LogFactory.getLog(getClass());

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private UserDetailsService userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private AuthenticationDetailsSource authenticationDetailsSource = new WebAuthenticationDetailsSource();

    private String cookieName = SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY;
	private String parameter = DEFAULT_PARAMETER;
    private boolean alwaysRemember;
    private String key;
    private int tokenValiditySeconds = 1209600; // 14 days

    public void afterPropertiesSet() throws Exception {
        Assert.hasLength(key);
        Assert.hasLength(parameter);
        Assert.hasLength(cookieName);
        Assert.notNull(userDetailsService);
    }

    /**
     * Template implementation which locates the Spring Security cookie, decodes it into
     * a delimited array of tokens and submits it to subclasses for processing
     * via the <tt>processAutoLoginCookie</tt> method.
     * <p>
     * The returned username is then used to load the UserDetails object for the user, which in turn
     * is used to create a valid authentication token.
     */
    public final Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
        String rememberMeCookie = extractRememberMeCookie(request);

        if (rememberMeCookie == null) {
            return null;
        }

        logger.debug("Remember-me cookie detected");

        UserDetails user = null;

        try {
            String[] cookieTokens = decodeCookie(rememberMeCookie);
            user = processAutoLoginCookie(cookieTokens, request, response);
            userDetailsChecker.check(user);
        } catch (CookieTheftException cte) {
            cancelCookie(request, response);
            throw cte;
        } catch (UsernameNotFoundException noUser) {
            cancelCookie(request, response);
            logger.debug("Remember-me login was valid but corresponding user not found.", noUser);
            return null;
        } catch (InvalidCookieException invalidCookie) {
            cancelCookie(request, response);
            logger.debug("Invalid remember-me cookie: " + invalidCookie.getMessage());
            return null;
        } catch (AccountStatusException statusInvalid) {
            cancelCookie(request, response);
            logger.debug("Invalid UserDetails: " + statusInvalid.getMessage());
            return null;
        } catch (RememberMeAuthenticationException e) {
            cancelCookie(request, response);
            logger.debug(e.getMessage());
            return null;
        }

        logger.debug("Remember-me cookie accepted");

        RememberMeAuthenticationToken auth = new RememberMeAuthenticationToken(key, user, user.getAuthorities());
        auth.setDetails(authenticationDetailsSource.buildDetails(request));

        return auth;
    }

    /**
     * Locates the Spring Security remember me cookie in the request.
     *
     * @param request the submitted request which is to be authenticated
     * @return the cookie value (if present), null otherwise.
     */
    private String extractRememberMeCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if ((cookies == null) || (cookies.length == 0)) {
            return null;
        }

        for (int i = 0; i < cookies.length; i++) {
            if (cookieName.equals(cookies[i].getName())) {
                return cookies[i].getValue();
            }
        }

        return null;
    }

    /**
     * Decodes the cookie and splits it into a set of token strings using the ":" delimiter.
     *
     * @param cookieValue the value obtained from the submitted cookie
     * @return the array of tokens.
     * @throws InvalidCookieException if the cookie was not base64 encoded.
     */
    protected String[] decodeCookie(String cookieValue) throws InvalidCookieException {
        for (int j = 0; j < cookieValue.length() % 4; j++) {
            cookieValue = cookieValue + "=";
        }

        if (!Base64.isArrayByteBase64(cookieValue.getBytes())) {
            throw new InvalidCookieException( "Cookie token was not Base64 encoded; value was '" + cookieValue + "'");
        }

        String cookieAsPlainText = new String(Base64.decodeBase64(cookieValue.getBytes()));

        return StringUtils.delimitedListToStringArray(cookieAsPlainText, DELIMITER);
    }

    /**
     * Inverse operation of decodeCookie.
     *
     * @param cookieTokens the tokens to be encoded.
     * @return base64 encoding of the tokens concatenated with the ":" delimiter.
     */
    protected String encodeCookie(String[] cookieTokens) {
        StringBuffer sb = new StringBuffer();
        for(int i=0; i < cookieTokens.length; i++) {
            sb.append(cookieTokens[i]);

            if (i < cookieTokens.length - 1) {
                sb.append(DELIMITER);
            }
        }

        String value = sb.toString();

        sb = new StringBuffer(new String(Base64.encodeBase64(value.getBytes())));

        while (sb.charAt(sb.length() - 1) == '=') {
            sb.deleteCharAt(sb.length() - 1);
        }

        return sb.toString();
    }

    public final void loginFail(HttpServletRequest request, HttpServletResponse response) {
        logger.debug("Interactive login attempt was unsuccessful.");
        cancelCookie(request, response);
        onLoginFail(request, response);
    }

    protected void onLoginFail(HttpServletRequest request, HttpServletResponse response) {}

    /**
     * Examines the incoming request and checks for the presence of the configured "remember me" parameter.
     * If it's present, or if <tt>alwaysRemember</tt> is set to true, calls <tt>onLoginSucces</tt>.
     */
    public final void loginSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication successfulAuthentication) {

        if (!rememberMeRequested(request, parameter)) {
            logger.debug("Remember-me login not requested.");
            return;
        }

        onLoginSuccess(request, response, successfulAuthentication);
    }

    /**
     * Called from loginSuccess when a remember-me login has been requested.
     * Typically implemented by subclasses to set a remember-me cookie and potentially store a record
     * of it if the implementation requires this.
     */
    protected abstract void onLoginSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication successfulAuthentication);

    /**
     * Allows customization of whether a remember-me login has been requested.
     * The default is to return true if <tt>alwaysRemember</tt> is set or the configured parameter name has
     * been included in the request and is set to the value "true".
     *
     * @param request the request submitted from an interactive login, which may include additional information
     * indicating that a persistent login is desired.
     * @param parameter the configured remember-me parameter name.
     *
     * @return true if the request includes information indicating that a persistent login has been
     * requested.
     */
    protected boolean rememberMeRequested(HttpServletRequest request, String parameter) {
        if (alwaysRemember) {
            return true;
        }

        if (!ServletRequestUtils.getBooleanParameter(request, parameter, false)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Did not send remember-me cookie (principal did not set parameter '" + parameter + "')");
            }
            return false;
        }

        return true;
    }

    /**
     * Called from autoLogin to process the submitted persistent login cookie. Subclasses should
     * validate the cookie and perform any additional management required.
     *
     * @param cookieTokens the decoded and tokenized cookie value
     * @param request the request
     * @param response the response, to allow the cookie to be modified if required.
     * @return the UserDetails for the corresponding user account if the cookie was validated successfully.
     * @throws RememberMeAuthenticationException if the cookie is invalid or the login is invalid for some
     * other reason.
     * @throws UsernameNotFoundException if the user account corresponding to the login cookie couldn't be found
     * (for example if the user has been removed from the system).
     */
    protected abstract UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request,
            HttpServletResponse response) throws RememberMeAuthenticationException, UsernameNotFoundException;

    /**
     * Sets a "cancel cookie" (with maxAge = 0) on the response to disable persistent logins.
     *
     * @param request
     * @param response
     */
    protected void cancelCookie(HttpServletRequest request, HttpServletResponse response) {
        logger.debug("Cancelling cookie");
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setMaxAge(0);
        cookie.setPath(StringUtils.hasLength(request.getContextPath()) ? request.getContextPath() : "/");

        response.addCookie(cookie);
    }

    /**
     * Sets the cookie on the response
     *
     * @param tokens the tokens which will be encoded to make the cookie value.
     * @param maxAge the value passed to {@link Cookie#setMaxAge(int)}
     * @param request the request
     * @param response the response to add the cookie to.
     */
    protected void setCookie(String[] tokens, int maxAge, HttpServletRequest request, HttpServletResponse response) {
        String cookieValue = encodeCookie(tokens);
        Cookie cookie = new Cookie(cookieName, cookieValue);
        cookie.setMaxAge(maxAge);
        cookie.setPath(StringUtils.hasLength(request.getContextPath()) ? request.getContextPath() : "/");
        response.addCookie(cookie);
    }

    /**
     * Implementation of <tt>LogoutHandler</tt>. Default behaviour is to call <tt>cancelCookie()</tt>.
     */
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (logger.isDebugEnabled()) {
            logger.debug( "Logout of user "
                    + (authentication == null ? "Unknown" : authentication.getName()));
        }
        cancelCookie(request, response);
    }

    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    public void setAlwaysRemember(boolean alwaysRemember) {
        this.alwaysRemember = alwaysRemember;
    }

    public void setParameter(String parameter) {
        this.parameter = parameter;
    }

    public String getParameter() {
        return parameter;
    }

    protected UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public void setTokenValiditySeconds(int tokenValiditySeconds) {
        this.tokenValiditySeconds = tokenValiditySeconds;
    }

    protected int getTokenValiditySeconds() {
        return tokenValiditySeconds;
    }

    protected AuthenticationDetailsSource getAuthenticationDetailsSource() {
        return authenticationDetailsSource;
    }
}
