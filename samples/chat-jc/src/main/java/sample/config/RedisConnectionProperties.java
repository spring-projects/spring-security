package sample.config;

import java.io.IOException;

/**
 * @author Rob Winch
 */
public interface RedisConnectionProperties {
    int getPort() throws IOException;
}
