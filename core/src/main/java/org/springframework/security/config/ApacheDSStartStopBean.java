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
import org.apache.directory.server.core.DirectoryService;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Properties;
import java.io.File;

/**
 * Starts and stops the embedded apacheDS server defined by the supplied configuration.
 * Used by {@link LdapBeanDefinitionParser}. An instance will be stored in the context for
 * each embedded server instance and its InitializingBean and DisposableBean implementations
 * used to start and stop the server, respectively.
 *
 * <p>
 * If used repeatedly in a single JVM process with the same configuration (for example, when
 * repeatedly loading an application context during testing), it's important that the
 * application context is closed to allow the bean to be disposed of and the server shutdown
 * prior to attempting to start it again.
 *
 * @author Luke Taylor
 * @version $Id$
 */
class ApacheDSStartStopBean implements InitializingBean, DisposableBean, ApplicationContextAware {
    private Log logger = LogFactory.getLog(getClass());

    private MutableServerStartupConfiguration configuration;
    private ApplicationContext ctxt;
    private File workingDir;
    /** The instance Id of the Apache DS DirectoryServer instance */
    private String instanceId;

    private ContextSource contextSource;

    public ApacheDSStartStopBean(MutableServerStartupConfiguration configuration, ContextSource contextSource) {
        this.configuration = configuration;
        this.contextSource = contextSource;
    }

    public void afterPropertiesSet() throws Exception {
        String apacheWorkDir = System.getProperty("apacheDSWorkDir");

        if (apacheWorkDir == null) {
            apacheWorkDir = System.getProperty("java.io.tmpdir") + File.separator + "apacheds-spring-security";
        }

        workingDir = new File(apacheWorkDir);

        configuration.setWorkingDirectory(workingDir);

        // We need this for shutdown
        instanceId = configuration.getInstanceId();

        startDirectoryService();

        // Import any ldif files
        Resource[] ldifs = ctxt.getResources("classpath:*.ldif");

        // Note that we can't just import using the ServerContext returned
        // from starting Apace DS, apparently because of the long-running issue DIRSERVER-169.
        // We need a standard context.
        DirContext dirContext = contextSource.getReadWriteContext();

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

    private void startDirectoryService() throws NamingException {
        DirectoryService ds = DirectoryService.getInstance(instanceId);

        if (ds.isStarted()) {
            throw new IllegalStateException("A DirectoryService with Id '" + instanceId + "' is already running.");
        }

        logger.info("Starting directory server with Id '" + instanceId + "'");
        Properties env = new Properties();

        env.setProperty(Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName());
        env.setProperty(Context.SECURITY_AUTHENTICATION, "simple");
        env.setProperty(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.setProperty(Context.SECURITY_CREDENTIALS, "secret");
        env.putAll(configuration.toJndiEnvironment());

        new InitialDirContext(env);        
    }

    public void destroy() throws Exception {
        Properties env = new Properties();
        env.setProperty(Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName());
        env.setProperty(Context.SECURITY_AUTHENTICATION, "simple");
        env.setProperty(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.setProperty(Context.SECURITY_CREDENTIALS, "secret");

        ShutdownConfiguration shutdown = new ShutdownConfiguration(instanceId);
        env.putAll(shutdown.toJndiEnvironment());

        logger.info("Shutting down directory server with Id '" + instanceId + "'");
        new InitialContext(env);

        if (workingDir.exists()) {
            logger.info("Deleting working directory " + workingDir.getAbsolutePath());
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
