package org.springframework.security.integration;

import javax.servlet.ServletContext;

import net.sourceforge.jwebunit.junit.WebTester;

import org.mortbay.jetty.Server;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.jetty.webapp.WebAppContext;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.util.StringUtils;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.servlet.DispatcherServlet;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;

/**
 * Base class which allows the application to be started with a particular Spring application
 * context. Subclasses override the <tt>getContextConfigLocations</tt> method to return
 * a list of context file names which is passed to the <tt>ContextLoaderListener</tt> when
 * starting up the webapp.
 *
 * @author Luke Taylor
 */
public abstract class AbstractWebServerIntegrationTests {
    private Server server;
    private final Object SERVER_LOCK = new Object();
    protected final WebTester tester = new WebTester();

    /**
     * Override to set the application context files that should be loaded or return null
     * to use web.xml.
     */
    protected abstract String getContextConfigLocations();

    protected String getContextPath() {
        return "/testapp";
    }

    @BeforeClass
    public void startServer() throws Exception {
        synchronized(SERVER_LOCK) {
            if (server == null) {
                //System.setProperty("DEBUG", "true");
                //System.setProperty("VERBOSE", "true");
                //System.setProperty("IGNORED", "true");
                server = new Server(0);
                server.addHandler(createWebContext());
                server.start();
                tester.getTestContext().setBaseUrl(getBaseUrl());
            }
        }
    }

    @SuppressWarnings("unchecked")
    private WebAppContext createWebContext() {
        WebAppContext webCtx = new WebAppContext("src/main/webapp", getContextPath());

        if (StringUtils.hasText(getContextConfigLocations())) {
            webCtx.addEventListener(new ContextLoaderListener());
            webCtx.addEventListener(new HttpSessionEventPublisher());
            webCtx.getInitParams().put("contextConfigLocation", getContextConfigLocations());
        }

        ServletHolder servlet = new ServletHolder();
        servlet.setName("testapp");
        servlet.setClassName(DispatcherServlet.class.getName());
        webCtx.addServlet(servlet, "*.htm");

        return webCtx;
    }

    @AfterClass
    public void stopServer() throws Exception {
        synchronized(SERVER_LOCK) {
            if (server != null) {
                server.stop();
            }
            server = null;
        }
    }

    @AfterMethod
    public void resetWebConversation() {
        tester.closeBrowser();
    }

    protected final String getBaseUrl() {
        int port = server.getConnectors()[0].getLocalPort();
        return "http://localhost:" + port + getContextPath() + "/";
    }

    protected final Object getBean(String beanName) {
        return getAppContext().getBean(beanName);
    }

    private WebApplicationContext getAppContext() {
        ServletContext servletCtx = ((WebAppContext)server.getHandler()).getServletContext();
        WebApplicationContext appCtx =
                WebApplicationContextUtils.getRequiredWebApplicationContext(servletCtx);
        return appCtx;
    }

//    protected final HttpUnitDialog getDialog() {
//        return tester.getDialog();
//    }

    protected final void submit() {
        tester.submit();
    }

    protected final void beginAt(String url) {
        tester.beginAt(url);
    }

    protected final void setTextField(String name, String value) {
        tester.setTextField(name, value);
    }

    protected final void assertFormPresent() {
        tester.assertFormPresent();
    }

    protected final void assertTextPresent(String text) {
        tester.assertTextPresent(text);
    }

    // Security-specific utility methods

    protected void login(String username, String password) {
        assertFormPresent();
        setTextField("j_username", username);
        setTextField("j_password", password);
        submit();
    }
}
