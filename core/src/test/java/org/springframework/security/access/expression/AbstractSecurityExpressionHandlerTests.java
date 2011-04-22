package org.springframework.security.access.expression;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import org.junit.*;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.expression.Expression;
import org.springframework.security.core.Authentication;

import java.util.*;

/**
 * @author Luke Taylor
 */
public class AbstractSecurityExpressionHandlerTests {
    private AbstractSecurityExpressionHandler<Object> handler;

    @Before
    public void setUp() throws Exception {
        handler = new AbstractSecurityExpressionHandler<Object>() {
            @Override
            protected SecurityExpressionRoot createSecurityExpressionRoot(Authentication authentication, Object o) {
                return new SecurityExpressionRoot(authentication) {};
            }
        };
    }

    @Test
    public void beanNamesAreCorrectlyResolved() throws Exception {
        handler.setApplicationContext(new AnnotationConfigApplicationContext(TestConfiguration.class));

        Expression expression = handler.getExpressionParser().parseExpression("@number10.compareTo(@number20) < 0");
        assertTrue((Boolean) expression.getValue(handler.createEvaluationContext(mock(Authentication.class), new Object())));
    }
}

@Configuration
class TestConfiguration {

    @Bean
    Integer number10() {
        return 10;
    }

    @Bean
    Integer number20() {
        return 20;
    }
}
