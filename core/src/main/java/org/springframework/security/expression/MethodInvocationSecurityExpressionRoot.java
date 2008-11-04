package org.springframework.security.expression;

import org.springframework.security.Authentication;

public class MethodInvocationSecurityExpressionRoot extends SecurityExpressionRoot {

    MethodInvocationSecurityExpressionRoot(Authentication a) {
        super(a);
    }

}
