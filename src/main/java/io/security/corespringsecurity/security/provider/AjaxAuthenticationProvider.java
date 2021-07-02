package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
public class AjaxAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String)authentication.getCredentials();

        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);
        Account account = accountContext.getAccount();

        // 패스워드 매칭
        if (!passwordEncoder.matches(password, account.getPassword()))
            throw new BadCredentialsException("BadCredentialsException");

        // 인증 토큰을 발급해야 한다. => Authentication 를 상속한 객체이다.
        // principal => account, credentials => password
        return new AjaxAuthenticationToken(account, null, accountContext.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return AjaxAuthenticationToken.class.isAssignableFrom(clazz);
    }
}
