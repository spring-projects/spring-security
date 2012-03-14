package org.springframework.security.web.authentication.rememberme;

import java.lang.reflect.Method;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;

/**
 * Base class for RememberMeServices implementations.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 2.0
 */
public abstract class AbstractRememberMeServices implements RememberMeServices, InitializingBean, LogoutHandler {
    //~ Static fields/initializers =====================================================================================

    public static final String SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY = "SPRING_SECURITY_REMEMBER_ME_COOKIE";
    public static final String DEFAULT_PARAMETER = "_spring_security_remember_me";
    public static final int TWO_WEEKS_S = 1209600;

    private static final String DELIMITER = ":";

    //~ Instance fields ================================================================================================
    protected final Log logger = LogFactory.getLog(getClass());

    protected final MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private UserDetailsService userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    private String cookieName = SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY;
    private String parameter = DEFAULT_PARAMETER;
    private boolean alwaysRemember;
    private String key;
    private int tokenValiditySeconds = TWO_WEEKS_S;
    private Boolean useSecureCookie = null;
    private Method setHttpOnlyMethod;
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    /**
     * @deprecated Use constructor injection
     */
    @Deprecated
    protected AbstractRememberMeServices() {
        this.setHttpOnlyMethod = ReflectionUtils.findMethod(Cookie.class,"setHttpOnly", boolean.class);
    }

    protected AbstractRememberMeServices(String key, UserDetailsService userDetailsService) {
        Assert.hasLength(key, "key cannot be empty or null");
        Assert.notNull(userDetailsService, "UserDetailsService cannot be null");
        this.key = key;
        this.userDetailsService = userDetailsService;
        this.setHttpOnlyMethod = ReflectionUtils.findMethod(Cookie.class,"setHttpOnly", boolean.class);
    }

    public void afterPropertiesSet() throws Exception {
        Assert.hasLength(key);
        Assert.notNull(userDetailsService, "A UserDetailsService is required");
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

        if (rememberMeCookie.length() == 0) {
            logger.debug("Cookie was empty");
            cancelCookie(request, response);
            return null;
        }

        UserDetails user = null;

        try {
            String[] cookieTokens = decodeCookie(rememberMeCookie);
            user = processAutoLoginCookie(cookieTokens, request, response);
            userDetailsChecker.check(user);

            logger.debug("Remember-me cookie accepted");

            return createSuccessfulAuthentication(request, user);
        } catch (CookieTheftException cte) {
            cancelCookie(request, response);
            throw cte;
        } catch (UsernameNotFoundException noUser) {
            logger.debug("Remember-me login was valid but corresponding user not found.", noUser);
        } catch (InvalidCookieException invalidCookie) {
            logger.debug("Invalid remember-me cookie: " + invalidCookie.getMessage());
        } catch (AccountStatusException statusInvalid) {
            logger.debug("Invalid UserDetails: " + statusInvalid.getMessage());
        } catch (RememberMeAuthenticationException e) {
            logger.debug(e.getMessage());
        }

        cancelCookie(request, response);
        return null;
    }

    /**
     * Locates the Spring Security remember me cookie in the request and returns its value.
     * The cookie is searched for by name and also by matching the context path to the cookie path.
     *
     * @param request the submitted request which is to be authenticated
     * @return the cookie value (if present), null otherwise.
     */
    protected String extractRememberMeCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if ((cookies == null) || (cookies.length == 0)) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        return null;
    }

    /**
     * Creates the final <tt>Authentication</tt> object returned from the <tt>autoLogin</tt> method.
     * <p>
     * By default it will create a <tt>RememberMeAuthenticationToken</tt> instance.
     *
     * @param request       the original request. The configured <tt>AuthenticationDetailsSource</tt> will
     *                      use this to build the details property of the returned object.
     * @param user          the <tt>UserDetails</tt> loaded from the <tt>UserDetailsService</tt>. This will be
     *                      stored as the principal.
     *
     * @return the <tt>Authentication</tt> for the remember-me authenticated user
     */
    protected Authentication createSuccessfulAuthentication(HttpServletRequest request, UserDetails user) {
        RememberMeAuthenticationToken auth = new RememberMeAuthenticationToken(key, user,
                authoritiesMapper.mapAuthorities(user.getAuthorities()));
        auth.setDetails(authenticationDetailsSource.buildDetails(request));
        return auth;
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

        if (!Base64.isBase64(cookieValue.getBytes())) {
            throw new InvalidCookieException( "Cookie token was not Base64 encoded; value was '" + cookieValue + "'");
        }

        String cookieAsPlainText = new String(Base64.decode(cookieValue.getBytes()));

        String[] tokens = StringUtils.delimitedListToStringArray(cookieAsPlainText, DELIMITER);

        if ((tokens[0].equalsIgnoreCase("http") || tokens[0].equalsIgnoreCase("https")) && tokens[1].startsWith("//")) {
            // Assume we've accidentally split a URL (OpenID identifier)
            String[] newTokens = new String[tokens.length - 1];
            newTokens[0] = tokens[0] + ":" + tokens[1];
            System.arraycopy(tokens, 2, newTokens, 1, newTokens.length - 1);
            tokens = newTokens;
        }

        return tokens;
    }

    /**
     * Inverse operation of decodeCookie.
     *
     * @param cookieTokens the tokens to be encoded.
     * @return base64 encoding of the tokens concatenated with the ":" delimiter.
     */
    protected String encodeCookie(String[] cookieTokens) {
        StringBuilder sb = new StringBuilder();
        for(int i=0; i < cookieTokens.length; i++) {
            sb.append(cookieTokens[i]);

            if (i < cookieTokens.length - 1) {
                sb.append(DELIMITER);
            }
        }

        String value = sb.toString();

        sb = new StringBuilder(new String(Base64.encode(value.getBytes())));

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

        String paramValue = request.getParameter(parameter);

        if (paramValue != null) {
            if (paramValue.equalsIgnoreCase("true") || paramValue.equalsIgnoreCase("on") ||
                    paramValue.equalsIgnoreCase("yes") || paramValue.equals("1")) {
                return true;
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Did not send remember-me cookie (principal did not set parameter '" + parameter + "')");
        }

        return false;
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
     */
    protected void cancelCookie(HttpServletRequest request, HttpServletResponse response) {
        logger.debug("Cancelling cookie");
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setMaxAge(0);
        cookie.setPath(getCookiePath(request));

        response.addCookie(cookie);
    }

    /**
     * Sets the cookie on the response.
     *
     * By default a secure cookie will be used if the connection is secure. You can set the {@code useSecureCookie}
     * property to {@code false} to override this. If you set it to {@code true}, the cookie will always be flagged
     * as secure. If Servlet 3.0 is used, the cookie will be marked as HttpOnly.
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
        cookie.setPath(getCookiePath(request));

        if (useSecureCookie == null) {
            cookie.setSecure(request.isSecure());
        } else {
            cookie.setSecure(useSecureCookie);
        }

        if(setHttpOnlyMethod != null) {
            ReflectionUtils.invokeMethod(setHttpOnlyMethod, cookie, Boolean.TRUE);
        } else if (logger.isDebugEnabled()) {
            logger.debug("Note: Cookie will not be marked as HttpOnly because you are not using Servlet 3.0 (Cookie#setHttpOnly(boolean) was not found).");
        }

        response.addCookie(cookie);
    }

    private String getCookiePath(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return contextPath.length() > 0 ? contextPath : "/";
    }

    /**
     * Implementation of {@code LogoutHandler}. Default behaviour is to call {@code cancelCookie()}.
     */
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (logger.isDebugEnabled()) {
            logger.debug( "Logout of user "
                    + (authentication == null ? "Unknown" : authentication.getName()));
        }
        cancelCookie(request, response);
    }

    public void setCookieName(String cookieName) {
        Assert.hasLength(cookieName, "Cookie name cannot be empty or null");
        this.cookieName = cookieName;
    }

    protected String getCookieName() {
        return cookieName;
    }

    public void setAlwaysRemember(boolean alwaysRemember) {
        this.alwaysRemember = alwaysRemember;
    }

    /**
     * Sets the name of the parameter which should be checked for to see if a remember-me has been requested
     * during a login request. This should be the same name you assign to the checkbox in your login form.
     *
     * @param parameter the HTTP request parameter
     */
    public void setParameter(String parameter) {
        Assert.hasText(parameter, "Parameter name cannot be empty or null");
        this.parameter = parameter;
    }

    public String getParameter() {
        return parameter;
    }

    protected UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    /**
     *
     * @deprecated Use constructor injection
     */
    @Deprecated
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        Assert.notNull(userDetailsService, "UserDetailsService canot be null");
        this.userDetailsService = userDetailsService;
    }

    /**
     *
     * @deprecated Use constructor injection
     */
    @Deprecated
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

    /**
     * Whether the cookie should be flagged as secure or not. Secure cookies can only be sent over an HTTPS connection
     * and thus cannot be accidentally submitted over HTTP where they could be intercepted.
     * <p>
     * By default the cookie will be secure if the request is secure. If you only want to use remember-me over
     * HTTPS (recommended) you should set this property to {@code true}.
     *
     * @param useSecureCookie set to {@code true} to always user secure cookies, {@code false} to disable their use.
     */
    public void setUseSecureCookie(boolean useSecureCookie) {
        this.useSecureCookie = useSecureCookie;
    }

    protected AuthenticationDetailsSource<HttpServletRequest,?> getAuthenticationDetailsSource() {
        return authenticationDetailsSource;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest,?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource cannot be null");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    /**
     * Sets the strategy to be used to validate the {@code UserDetails} object obtained for
     * the user when processing a remember-me cookie to automatically log in a user.
     *
     * @param userDetailsChecker
     *          the strategy which will be passed the user object to allow it to be rejected if account should not
     *          be allowed to authenticate (if it is locked, for example). Defaults to a
     *          {@code AccountStatusUserDetailsChecker} instance.
     *
     */
    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
        this.userDetailsChecker = userDetailsChecker;
    }

    public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
        this.authoritiesMapper = authoritiesMapper;
    }
}
