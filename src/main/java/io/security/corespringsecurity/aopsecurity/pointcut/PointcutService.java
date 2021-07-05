package io.security.corespringsecurity.aopsecurity.pointcut;

import org.springframework.stereotype.Service;

@Service
public class PointcutService {
    public void pointcutSecured() {
        System.out.println("pointcutSecured");
    }
}
