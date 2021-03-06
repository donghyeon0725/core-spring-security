package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * account 를 저장해두고 UserDetails 로 변환할 수 있도록 만든 객체
 * */
public class AccountContext extends User {
    private final Account account;

    public AccountContext(Account account) {

        // GrantedAuthority interface 으로 우리가 만든 String 을 Role 객체로 변환하는 것이 가능한데 이 interface 를 구현한 클래스가 SimpleGrantedAuthority이다.
        super(account.getUsername(), account.getPassword(),
                account.getUserRoles().stream().map(s -> new SimpleGrantedAuthority(s.getRoleName())).collect(Collectors.toList()));
        this.account = account;
    }

    // GrantedAuthority

    public Account getAccount() {
        return account;
    }
}
