package org.springframework.security.config;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.powermock.api.mockito.PowerMockito.*;

import org.apache.commons.logging.Log;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.util.ClassUtils;

/**
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.0
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ClassUtils.class})
public class SecurityNamespaceHandlerTests {
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private static final String XML_AUTHENTICATION_MANAGER =
            "<authentication-manager>"+
            "  <authentication-provider>"+
            "    <user-service id='us'>"+
            "      <user name='bob' password='bobspassword' authorities='ROLE_A' />" +
            "    </user-service>"+
            "  </authentication-provider>"+
            "</authentication-manager>";
    private static final String XML_HTTP_BLOCK = "<http auto-config='true'/>";
    private static final String FILTER_CHAIN_PROXY_CLASSNAME = "org.springframework.security.web.FilterChainProxy";

    @Test
    public void constructionSucceeds() {
        new SecurityNamespaceHandler();
        // Shameless class coverage stats boosting
        new BeanIds() {};
        new Elements() {};
    }

    @Test
    public void pre32SchemaAreNotSupported() throws Exception {
        try {
            new InMemoryXmlApplicationContext(
                    "<user-service id='us'>" +
                    "  <user name='bob' password='bobspassword' authorities='ROLE_A' />" +
                    "</user-service>", "3.0.3", null
            );
            fail("Expected BeanDefinitionParsingException");
        } catch (BeanDefinitionParsingException expected) {
            assertTrue(expected.getMessage().contains("You cannot use a spring-security-2.0.xsd"));
        }
    }

    // SEC-1868
    @Test
    public void initDoesNotLogErrorWhenFilterChainProxyFailsToLoad() throws Exception {
        String className = "javax.servlet.Filter";
        spy(ClassUtils.class);
        doThrow(new NoClassDefFoundError(className)).when(ClassUtils.class,"forName",eq(FILTER_CHAIN_PROXY_CLASSNAME),any(ClassLoader.class));

        Log logger = mock(Log.class);
        SecurityNamespaceHandler handler = new SecurityNamespaceHandler();
        WhiteboxImpl.setInternalState(handler, Log.class, logger);

        handler.init();

        verifyStatic();
        ClassUtils.forName(eq(FILTER_CHAIN_PROXY_CLASSNAME),any(ClassLoader.class));
        verifyZeroInteractions(logger);
    }

    @Test
    public void filterNoClassDefFoundError() throws Exception {
        String className = "javax.servlet.Filter";
        thrown.expect(BeanDefinitionParsingException.class);
        thrown.expectMessage("NoClassDefFoundError: "+className);
        spy(ClassUtils.class);
        doThrow(new NoClassDefFoundError(className)).when(ClassUtils.class,"forName",eq(FILTER_CHAIN_PROXY_CLASSNAME),any(ClassLoader.class));
        new InMemoryXmlApplicationContext(
                XML_AUTHENTICATION_MANAGER +
                XML_HTTP_BLOCK);
    }

    @Test
    public void filterNoClassDefFoundErrorNoHttpBlock() throws Exception {
        String className = "javax.servlet.Filter";
        spy(ClassUtils.class);
        doThrow(new NoClassDefFoundError(className)).when(ClassUtils.class,"forName",eq(FILTER_CHAIN_PROXY_CLASSNAME),any(ClassLoader.class));
        new InMemoryXmlApplicationContext(
                XML_AUTHENTICATION_MANAGER);
        // should load just fine since no http block
    }

    @Test
    public void filterChainProxyClassNotFoundException() throws Exception {
        String className = FILTER_CHAIN_PROXY_CLASSNAME;
        thrown.expect(BeanDefinitionParsingException.class);
        thrown.expectMessage("ClassNotFoundException: "+className);
        spy(ClassUtils.class);
        doThrow(new ClassNotFoundException(className)).when(ClassUtils.class,"forName",eq(FILTER_CHAIN_PROXY_CLASSNAME),any(ClassLoader.class));
        new InMemoryXmlApplicationContext(
                XML_AUTHENTICATION_MANAGER +
                XML_HTTP_BLOCK);
    }

    @Test
    public void filterChainProxyClassNotFoundExceptionNoHttpBlock() throws Exception {
        String className = FILTER_CHAIN_PROXY_CLASSNAME;
        spy(ClassUtils.class);
        doThrow(new ClassNotFoundException(className)).when(ClassUtils.class,"forName",eq(FILTER_CHAIN_PROXY_CLASSNAME),any(ClassLoader.class));
        new InMemoryXmlApplicationContext(
                XML_AUTHENTICATION_MANAGER);
        // should load just fine since no http block
    }
}
