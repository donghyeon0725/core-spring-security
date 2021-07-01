package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import io.security.corespringsecurity.security.service.CustomUserDetailsService;
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
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    /**
     * 인증
     * authentication 는 AuthenticationManager 가 주는 Authentication 정보가 담겨 올 것이므로, 여기서 사용자 정보를 추출할 수 있다.
     * ProviderManager가 AuthenticationManager의 구현체이다.
     * */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = (String)authentication.getCredentials();

        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);
        Account account = accountContext.getAccount();

        // 패스워드 매칭
        if (!passwordEncoder.matches(password, account.getPassword()))
            throw new BadCredentialsException("BadCredentialsException");

        FormWebAuthenticationDetails details = (FormWebAuthenticationDetails) authentication.getDetails();
        if (details.getSecretKey() == null || !"secret".equals(details.getSecretKey()))
            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");

        // 인증 토큰을 발급해야 한다. => Authentication 를 상속한 객체이다.
        // principal => account, credentials => password
        return new UsernamePasswordAuthenticationToken(account, null, accountContext.getAuthorities());
    }

    /**
     * 인증을 지원하는지
     * 이 타입이 맞으면, 자동으로 Provider로 선택 된다.
     * */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);

    }
}
