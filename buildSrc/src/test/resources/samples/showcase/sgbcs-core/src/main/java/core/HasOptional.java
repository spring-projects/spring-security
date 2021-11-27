package core;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class HasOptional {

	public static void doStuffWithOptionalDependency() {
		Logger logger = LoggerFactory.getLogger(HasOptional.class);
		logger.debug("This is optional");
	}
}
