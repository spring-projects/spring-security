package org.springframework.security.web.headers.frameoptions;

import org.springframework.util.Assert;

import java.util.regex.Pattern;

/**
 * Implementation which uses a regular expression to validate the supplied origin.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public class RegExpAllowFromStrategy extends RequestParameterAllowFromStrategy {

    private final Pattern pattern;

    public RegExpAllowFromStrategy(String pattern) {
        Assert.hasText(pattern, "Pattern cannot be empty.");
        this.pattern = Pattern.compile(pattern);
    }

    @Override
    protected boolean allowed(String from) {
        return pattern.matcher(from).matches();
    }
}
