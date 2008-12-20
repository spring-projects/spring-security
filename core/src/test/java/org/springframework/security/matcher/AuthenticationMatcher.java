package org.springframework.security.matcher;

import org.hamcrest.Description;
import org.hamcrest.Factory;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.springframework.security.Authentication;

public class AuthenticationMatcher extends TypeSafeMatcher<Authentication> {
    private String username;
    private String password;

    @Override
    public boolean matchesSafely(Authentication auth) {
        if (!username.equals(auth.getName())) {
            return false;
        }

        if (password != null && !password.equals(auth.getCredentials())) {
            return false;
        }

        return true;
    }

    public void describeTo(Description d) {
        d.appendText("an authentication object with username = '" + username + "'");
        if (password != null) {
            d.appendText(", password = '" + password + "'");
        }
    }

    @Factory
    public static Matcher<Authentication> anAuthenticationWithUsername(String name) {
        AuthenticationMatcher matcher = new AuthenticationMatcher();
        matcher.username = name;
        return matcher;
    }

    @Factory
    public static Matcher<Authentication> anAuthenticationWithUsernameAndPassword(String name, String password) {
        AuthenticationMatcher matcher = new AuthenticationMatcher();
        matcher.username = name;
        matcher.password = password;
        return matcher;

    }
}
