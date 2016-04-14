package org.springframework.security.jackson2;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

/**
 * @author Jitenra Singh
 */
@RunWith(MockitoJUnitRunner.class)
public abstract class AbstractMixinTests {

    protected ObjectMapper buildObjectMapper() {
        ObjectMapper mapper = new ObjectMapper()
                .enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
        mapper.setVisibilityChecker(mapper.getVisibilityChecker().withVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY));
        return mapper;
    }
}
