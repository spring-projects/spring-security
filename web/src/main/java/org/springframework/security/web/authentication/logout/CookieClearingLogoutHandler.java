package org.springframework.security.web.authentication.logout;

import java.util.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A logout handler which clears a defined list of cookies, using the context path as the
 * cookie path.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public final class CookieClearingLogoutHandler implements LogoutHandler {
    private final List<String> cookiesToClear;

    public CookieClearingLogoutHandler(String... cookiesToClear) {
        Assert.notNull(cookiesToClear, "List of cookies cannot be null");
        this.cookiesToClear = Arrays.asList(cookiesToClear);
    }

    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        for (String cookieName : cookiesToClear) {
            Cookie cookie = new Cookie(cookieName, null);
            cookie.setPath(request.getContextPath());
            cookie.setMaxAge(0);
            response.addCookie(cookie);
        }
    }
}
