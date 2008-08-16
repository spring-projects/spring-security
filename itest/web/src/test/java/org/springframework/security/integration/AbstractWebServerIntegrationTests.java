package org.springframework.security.integration;

import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.util.StringUtils;

import net.sourceforge.jwebunit.WebTester;

import org.mortbay.jetty.Server;
import org.mortbay.jetty.webapp.WebAppContext;

import javax.servlet.ServletContext;

import org.testng.annotations.*;

import com.meterware.httpunit.WebConversation;

/**
 * @author Luke Taylor
 * @version $Id$
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
    
    protected WebAppContext createWebContext() {
        WebAppContext webCtx = new WebAppContext("src/main/webapp", getContextPath());
    	
		if (StringUtils.hasText(getContextConfigLocations())) {
			webCtx.addEventListener(new ContextLoaderListener());
			webCtx.getInitParams().put("contextConfigLocation", getContextConfigLocations());
		}
		
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
    	tester.getTestContext().setWebClient(new WebConversation());
    }
    
    private final String getBaseUrl() {
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
//    	return tester.getDialog();
//    }

    protected final void submit() {
        tester.submit();
    }

    protected final void beginAt(String url) {
        tester.beginAt(url);
    }

    protected final void setFormElement(String name, String value) {
        tester.setFormElement(name, value);
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
	    setFormElement("j_username", username);
	    setFormElement("j_password", password);
	    submit();    	
	}
}
