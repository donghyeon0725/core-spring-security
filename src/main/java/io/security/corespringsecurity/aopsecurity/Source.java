package io.security.corespringsecurity.aopsecurity;

import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Component;

@Component
public class Source {

    @Secured("ROLE_USER")
    public String getSource() {
        return "source";
    }
}
