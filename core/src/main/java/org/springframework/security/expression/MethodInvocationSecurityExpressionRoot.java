package org.springframework.security.expression;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.Authentication;

public class MethodInvocationSecurityExpressionRoot extends SecurityExpressionRoot {

    MethodInvocationSecurityExpressionRoot(Authentication a, MethodInvocation mi) {
        super(a);

        mi.getArguments();
    }

}
