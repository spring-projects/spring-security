package org.springframework.security;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

import junit.framework.Assert;

import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.weaver.tools.PointcutExpression;
import org.aspectj.weaver.tools.PointcutParser;
import org.aspectj.weaver.tools.PointcutPrimitive;
import org.junit.Test;

/**
 * A quick play with AspectJ pointcut parsing. Was contemplating using this for MapBasedMethodDefinitionSource refactoring,
 * but decided to revisit at a future point. Requires aspectjweaver-1.5.3.jar in classpath.
 * 
 * @author Ben Alex
 */

public class AspectJParsingTests {
    private static final Set DEFAULT_SUPPORTED_PRIMITIVES = new HashSet();

    @Pointcut("execution(int TargetObject.countLength(String))")
    public void goodPointcut() {}

    static {
        DEFAULT_SUPPORTED_PRIMITIVES.add(PointcutPrimitive.CALL);
        DEFAULT_SUPPORTED_PRIMITIVES.add(PointcutPrimitive.EXECUTION);
        DEFAULT_SUPPORTED_PRIMITIVES.add(PointcutPrimitive.ARGS);
        DEFAULT_SUPPORTED_PRIMITIVES.add(PointcutPrimitive.REFERENCE);
        DEFAULT_SUPPORTED_PRIMITIVES.add(PointcutPrimitive.THIS);
        DEFAULT_SUPPORTED_PRIMITIVES.add(PointcutPrimitive.TARGET);
        DEFAULT_SUPPORTED_PRIMITIVES.add(PointcutPrimitive.WITHIN);
        DEFAULT_SUPPORTED_PRIMITIVES.add(PointcutPrimitive.AT_ANNOTATION);
        DEFAULT_SUPPORTED_PRIMITIVES.add(PointcutPrimitive.AT_WITHIN);
        DEFAULT_SUPPORTED_PRIMITIVES.add(PointcutPrimitive.AT_ARGS);
        DEFAULT_SUPPORTED_PRIMITIVES.add(PointcutPrimitive.AT_TARGET);
    }

    @Test
    public void testMatches() throws Exception {
        PointcutParser parser = PointcutParser.getPointcutParserSupportingSpecifiedPrimitivesAndUsingContextClassloaderForResolution(DEFAULT_SUPPORTED_PRIMITIVES);
        PointcutExpression expression = parser.parsePointcutExpression("org.springframework.security.AspectJParsingTests.goodPointcut()");

        Method exec = OtherTargetObject.class.getMethod("countLength", new Class[] {String.class});
        Assert.assertTrue(expression.matchesMethodExecution(exec).alwaysMatches());
    }

}
