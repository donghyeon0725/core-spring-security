package io.security.corespringsecurity.repository;


import io.security.corespringsecurity.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<Account, Long> {
    @Query("select a from Account a join fetch a.userRoles u where a.username = :username")
    Account findByUsername(@Param("username") String name);
}
