package sample.dms;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.springframework.util.Assert;

/**
 * @author Ben Alex
 * @version $Id$
 *
 */
public abstract class AbstractElement {
    /** The name of this token (a filename or directory segment name */
    private String name;

    /** The parent of this token (a directory, or null if referring to root) */
    private AbstractElement parent;

    /** The database identifier for this object (null if not persisted) */
    private Long id;

    /**
     * Constructor to use to represent a root element. A root element has an id of -1.
     */
    protected AbstractElement() {
        this.name = "/";
        this.parent = null;
        this.id = new Long(-1);
    }

    /**
     * Constructor to use to represent a non-root element.
     *
     * @param name name for this element (required, cannot be "/")
     * @param parent for this element (required, cannot be null)
     */
    protected AbstractElement(String name, AbstractElement parent) {
        Assert.hasText(name, "Name required");
        Assert.notNull(parent, "Parent required");
        Assert.notNull(parent.getId(), "The parent must have been saved in order to create a child");
        this.name = name;
        this.parent = parent;
    }

    public Long getId() {
        return id;
    }

    /**
     * @return the name of this token (never null, although will be "/" if root, otherwise it won't include separators)
     */
    public String getName() {
        return name;
    }

    public AbstractElement getParent() {
        return parent;
    }

    /**
     * @return the fully-qualified name of this element, including any parents
     */
    public String getFullName() {
        List<String> strings = new ArrayList<String>();
        AbstractElement currentElement = this;
        while (currentElement != null) {
            strings.add(0, currentElement.getName());
            currentElement = currentElement.getParent();
        }

        StringBuilder sb = new StringBuilder();
        String lastCharacter = null;
        for (Iterator<String> i = strings.iterator(); i.hasNext();) {
            String token = i.next();
            if (!"/".equals(lastCharacter) && lastCharacter != null) {
                sb.append("/");
            }
            sb.append(token);
            lastCharacter = token.substring(token.length()-1);
        }
        return sb.toString();
    }
}
