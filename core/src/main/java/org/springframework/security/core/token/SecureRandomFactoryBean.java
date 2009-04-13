package org.springframework.security.core.token;

import java.io.InputStream;
import java.security.SecureRandom;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.FileCopyUtils;

/**
 * Creates a {@link SecureRandom} instance.
 *
 * @author Ben Alex
 * @since 2.0.1
 * @version $Id$
 */
public class SecureRandomFactoryBean implements FactoryBean<SecureRandom> {

    private String algorithm = "SHA1PRNG";
    private Resource seed;

    public SecureRandom getObject() throws Exception {
        SecureRandom rnd = SecureRandom.getInstance(algorithm);

        if (seed != null) {
            // Seed specified, so use it
            byte[] seedBytes = FileCopyUtils.copyToByteArray(seed.getInputStream());
            rnd.setSeed(seedBytes);
        } else {
            // Request the next bytes, thus eagerly incurring the expense of default seeding
            rnd.nextBytes(new byte[1]);
        }

        return rnd;
    }

    public Class<SecureRandom> getObjectType() {
        return SecureRandom.class;
    }

    public boolean isSingleton() {
        return false;
    }

    /**
     * Allows the Pseudo Random Number Generator (PRNG) algorithm to be nominated. Defaults to "SHA1PRNG".
     *
     * @param algorithm to use (mandatory)
     */
    public void setAlgorithm(String algorithm) {
        Assert.hasText(algorithm, "Algorithm required");
        this.algorithm = algorithm;
    }

    /**
     * Allows the user to specify a resource which will act as a seed for the {@link SecureRandom}
     * instance. Specifically, the resource will be read into an {@link InputStream} and those
     * bytes presented to the {@link SecureRandom#setSeed(byte[])} method. Note that this will
     * simply supplement, rather than replace, the existing seed. As such, it is always safe to
     * set a seed using this method (it never reduces randomness).
     *
     * @param seed to use, or <code>null</code> if no additional seeding is needed
     */
    public void setSeed(Resource seed) {
        this.seed = seed;
    }
}
