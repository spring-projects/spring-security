package org.springframework.security.config;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.ldap.core.ContextSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.directory.server.configuration.MutableServerStartupConfiguration;
import org.apache.directory.server.jndi.ServerContextFactory;
import org.apache.directory.server.protocol.shared.store.LdifFileLoader;
import org.apache.directory.server.core.configuration.ShutdownConfiguration;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Properties;
import java.io.File;

/**
 * Starts and stops the embedded apacheDS server defined by the supplied configuration.
 * Used by {@link LdapBeanDefinitionParser}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
class ApacheDSStartStopBean implements InitializingBean, DisposableBean, ApplicationContextAware {
    private Log logger = LogFactory.getLog(getClass());

    private MutableServerStartupConfiguration configuration;
    private ApplicationContext ctxt;
    private File workingDir;

    public ApacheDSStartStopBean(MutableServerStartupConfiguration configuration) {
        this.configuration = configuration;
    }

    public void afterPropertiesSet() throws Exception {
        Properties env = new Properties();
        String apacheWorkDir = System.getProperty("apacheDSWorkDir");

        if (apacheWorkDir == null) {
            apacheWorkDir = System.getProperty("java.io.tmpdir") + File.separator + "apacheds-spring-security";
        }

        workingDir = new File(apacheWorkDir);

//        if (workingDir.exists()) {
//            logger.info("Deleting existing working directory " + workingDir.getAbsolutePath());
//            deleteDir(workingDir);
//        }

        configuration.setWorkingDirectory(workingDir);

        env.put(Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName());
        env.setProperty(Context.SECURITY_AUTHENTICATION, "simple");
        env.setProperty(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.setProperty(Context.SECURITY_CREDENTIALS, "secret");
        env.putAll(configuration.toJndiEnvironment());

        DirContext serverContext = new InitialDirContext(env);

        // Import any ldif files
        Resource[] ldifs = ctxt.getResources("classpath:*.ldif");


        DirContext dirContext = ((ContextSource)ctxt.getBean("contextSource")).getReadWriteContext();

        if(ldifs != null && ldifs.length > 0) {
            try {
                String ldifFile = ldifs[0].getFile().getAbsolutePath();
                LdifFileLoader loader = new LdifFileLoader(dirContext, ldifFile);
                loader.execute();
            } finally {
                dirContext.close();
            }
        }

    }

    public void destroy() throws Exception {
        Properties env = new Properties();
        env.setProperty(Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName());
        env.setProperty(Context.SECURITY_AUTHENTICATION, "simple");
        env.setProperty(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.setProperty(Context.SECURITY_CREDENTIALS, "secret");

        ShutdownConfiguration shutdown = new ShutdownConfiguration();
        env.putAll(shutdown.toJndiEnvironment());

        logger.info("Shutting down server...");
        new InitialContext(env);

        if (workingDir.exists()) {
            logger.info("Deleting working directory after shutting down " + workingDir.getAbsolutePath());
            deleteDir(workingDir);
        }

    }

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        ctxt = applicationContext;
    }

    public static boolean deleteDir(File dir) {
        if (dir.isDirectory()) {
            String[] children = dir.list();
            for (int i=0; i < children.length; i++) {
                boolean success = deleteDir(new File(dir, children[i]));
                if (!success) {
                    return false;
                }
            }
        }

        return dir.delete();
    }
}
