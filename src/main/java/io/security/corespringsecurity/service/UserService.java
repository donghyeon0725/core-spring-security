package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.domain.dto.UserDto;

import java.util.List;

public interface UserService {
    void createUser(Account account);

    UserDto getUser(Long id);

    List<Account> getUsers();

    void deleteUser(Long idx);
}
