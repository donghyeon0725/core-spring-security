package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * 스프링 시큐리티가 지정한 name 값을 주입 해 줍니다.
     * (usernameParameter 설정이 있다면 이 값으로)
     *
     * */
    @Override
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(name);

        // UsernameNotFoundException 도 시큐리티에서 기본 제공하는 Exception
        if (account == null)
            throw new UsernameNotFoundException("UsernameNotFoundException");

        // UserDetails 인터페이스를 구현한 User (기본제공) 을 상속 받은 객체이다.
        AccountContext accountContext = new AccountContext(account);

        return accountContext;
    }
}
