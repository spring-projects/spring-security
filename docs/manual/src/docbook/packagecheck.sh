CLASSPATH=`find ../../../.. -name *.jar | grep -v sources | xargs | sed "s/ /:/g"`

grep -o -e 'org.springframework.security\.[a-z]*\.[a-zA-Z0-9]*\.[A-Z][a-zA-z0-9]*' * | cut -d : -f 2 | xargs -n 1 javap -classpath "$CLASSPATH" | grep ERROR
