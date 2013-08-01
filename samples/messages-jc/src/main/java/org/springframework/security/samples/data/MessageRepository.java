package org.springframework.security.samples.data;

import org.springframework.data.repository.CrudRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;

public interface MessageRepository extends CrudRepository<Message, Long> {

    @Transactional
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    <S extends Message> S save(S entity);
}
