package org.springframework.security.web.headers.frameoptions;

import org.springframework.util.Assert;

import java.util.regex.Pattern;

/**
 * Implementation which uses a regular expression to validate the supplied
 * origin. If the value of the HTTP parameter matches the pattern, then the the
 * result will be ALLOW-FROM <paramter-value>.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class RegExpAllowFromStrategy extends AbstractRequestParameterAllowFromStrategy {

    private final Pattern pattern;

    /**
     * Creates a new instance
     *
     * @param pattern
     *            the Pattern to compare against the HTTP parameter value. If
     *            the pattern matches, the domain will be allowed, else denied.
     */
    public RegExpAllowFromStrategy(String pattern) {
        Assert.hasText(pattern, "Pattern cannot be empty.");
        this.pattern = Pattern.compile(pattern);
    }

    @Override
    protected boolean allowed(String allowFromOrigin) {
        return pattern.matcher(allowFromOrigin).matches();
    }
}
