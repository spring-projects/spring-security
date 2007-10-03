package org.springframework.security.config;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationContext;
import org.springframework.context.Lifecycle;
import org.springframework.core.io.Resource;
import org.springframework.ldap.core.ContextSource;
import org.springframework.util.Assert;
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
import java.io.IOException;

/**
 * Provides lifecycle services for the embedded apacheDS server defined by the supplied configuration.
 * Used by {@link LdapBeanDefinitionParser}. An instance will be stored in the application context for
 * each embedded server instance. It will start the server when the context is initialized and shut it down when
 * it is closed. It is intended for temporary embedded use and will not retain changes across start/stop boundaries. The
 * working directory is deleted on shutdown.
 *
 * <p>
 * If used repeatedly in a single JVM process with the same configuration (for example, when
 * repeatedly loading an application context during testing), it's important that the
 * application context is closed to allow the bean to be disposed of and the server shutdown
 * prior to attempting to start it again.
 * </p>
 *
 *
 *
 * @author Luke Taylor
 * @version $Id$
 */
class ApacheDSContainer implements InitializingBean, DisposableBean, Lifecycle, ApplicationContextAware {
    private Log logger = LogFactory.getLog(getClass());

    private MutableServerStartupConfiguration configuration;
    private ApplicationContext ctxt;
    private File workingDir;

    private ContextSource contextSource;
    private boolean running;

    public ApacheDSContainer(MutableServerStartupConfiguration configuration, ContextSource contextSource) {
        this.configuration = configuration;
        this.contextSource = contextSource;
    }

    public void afterPropertiesSet() throws Exception {
        if (workingDir != null) {
            return;
        }

        String apacheWorkDir = System.getProperty("apacheDSWorkDir");

        if (apacheWorkDir == null) {
            apacheWorkDir = System.getProperty("java.io.tmpdir") + File.separator + "apacheds-spring-security";
        }

        setWorkingDirectory(new File(apacheWorkDir));
        start();
    }

    public void destroy() throws Exception {
        stop();
    }

    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        ctxt = applicationContext;
    }

    private static boolean deleteDir(File dir) {
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

    public void setWorkingDirectory(File workingDir) {
        Assert.notNull(workingDir);

        if (workingDir.exists()) {
            throw new IllegalArgumentException("The specified working directory '" + workingDir.getAbsolutePath() +
                    "' already exists. Another directory service instance may be using it or it may be from a " +
                    " previous unclean shutdown. Please confirm and delete it or configure a different " +
                    "working directory");
        }

        this.workingDir = workingDir;

        configuration.setWorkingDirectory(workingDir);
    }


    public void start() {
        if (isRunning()) {
            return;
        }

        DirectoryService ds = DirectoryService.getInstance(configuration.getInstanceId());

        if (ds.isStarted()) {
            throw new IllegalStateException("A DirectoryService with Id '" + configuration.getInstanceId() + "' is already running.");
        }

        logger.info("Starting directory server with Id '" + configuration.getInstanceId() + "'");
        Properties env = new Properties();

        env.setProperty(Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName());
        env.setProperty(Context.SECURITY_AUTHENTICATION, "simple");
        env.setProperty(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.setProperty(Context.SECURITY_CREDENTIALS, "secret");
        env.putAll(configuration.toJndiEnvironment());

        try {
            new InitialDirContext(env);
        } catch (NamingException e) {
            logger.error("Failed to start directory service", e);
            return;
        }

        running = true;

        try {
            importLdifs();
        } catch (Exception e) {
            logger.error("Failed to import LDIF file(s)", e);
        }
    }

    private void importLdifs() throws IOException, NamingException {
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

    public void stop() {
        Properties env = new Properties();
        env.setProperty(Context.INITIAL_CONTEXT_FACTORY, ServerContextFactory.class.getName());
        env.setProperty(Context.SECURITY_AUTHENTICATION, "simple");
        env.setProperty(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.setProperty(Context.SECURITY_CREDENTIALS, "secret");

        ShutdownConfiguration shutdown = new ShutdownConfiguration(configuration.getInstanceId());
        env.putAll(shutdown.toJndiEnvironment());

        logger.info("Shutting down directory server with Id '" + configuration.getInstanceId() + "'");

        try {
            new InitialContext(env);
        } catch (NamingException e) {
            logger.error("Failed to shutdown directory server", e);
            return;
        }

        running = false;

        if (workingDir.exists()) {
            logger.info("Deleting working directory " + workingDir.getAbsolutePath());
            deleteDir(workingDir);
        }
    }

    public boolean isRunning() {
        return running;
    }
}
