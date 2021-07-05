package io.security.corespringsecurity.aopsecurity;

import org.springframework.stereotype.Service;

@Service
public class AopLiveMethodService {
    public void aopLiveMethodSecured() {
        System.out.println("aopLiveMethodSecured");
    }
}
