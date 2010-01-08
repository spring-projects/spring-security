package sample.dao;

import java.io.Serializable;


/**
 * The Interface GenericDAO.
 */
public interface GenericDAO<T extends Serializable, PK extends Serializable>
{
       /**
        * persist
        * @param transientInstance objet to persist
        */
    void persist(T transientInstance);


    /**
        * refresh
        * @param instance objet to refresh
        */
    void refresh(T instance);


    /**
        * delete
        * @param persistentInstance objet to delete
        */
    void delete(T persistentInstance);


    /**
        * merge
        * @param detachedInstance objet to merge
        * @return merged object
        */
    T merge(T detachedInstance);


    /**
        * read
        * @param id of object to read
        * @return read object
        */
    T read(PK id);
}