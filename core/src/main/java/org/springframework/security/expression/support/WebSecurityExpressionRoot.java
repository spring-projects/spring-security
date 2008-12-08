package org.springframework.security.expression.support;

import org.springframework.security.Authentication;
import org.springframework.security.intercept.web.FilterInvocation;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
class WebSecurityExpressionRoot extends SecurityExpressionRoot {
    private FilterInvocation filterInvocation;

    WebSecurityExpressionRoot(Authentication a, FilterInvocation fi) {
        super(a);
        this.filterInvocation = fi;
    }
}
