/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.IOException;
import java.net.ServerSocket;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import redis.embedded.RedisServer;

/**
 * Runs an embedded Redis instance. This is only necessary since we do not want users to
 * have to setup a Redis instance. In a production environment, this would not be used
 * since a Redis Server would be setup.
 *
 * @author Rob Winch
 */
@Configuration
public class EmbeddedRedisConfig {

	@Bean
	public static RedisServerBean redisServer() {
		return new RedisServerBean();
	}

	/**
	 * Implements BeanDefinitionRegistryPostProcessor to ensure this Bean is initialized
	 * before any other Beans. Specifically, we want to ensure that the Redis Server is
	 * started before RedisHttpSessionConfiguration attempts to enable Keyspace
	 * notifications.
	 */
	static class RedisServerBean implements InitializingBean, DisposableBean,
			BeanDefinitionRegistryPostProcessor, RedisConnectionProperties {
		private RedisServer redisServer;

		public void afterPropertiesSet() throws Exception {
			redisServer = new RedisServer(getPort());
			redisServer.start();
		}

		public void destroy() throws Exception {
			if (redisServer != null) {
				redisServer.stop();
			}
		}

		public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry)
				throws BeansException {
		}

		public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory)
				throws BeansException {
		}

		private Integer availablePort;

		public int getPort() throws IOException {
			if (availablePort == null) {
				ServerSocket socket = new ServerSocket(0);
				availablePort = socket.getLocalPort();
				socket.close();
			}
			return availablePort;
		}
	}
}