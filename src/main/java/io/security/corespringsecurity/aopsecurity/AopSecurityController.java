package io.security.corespringsecurity.aopsecurity;

import io.security.corespringsecurity.aopsecurity.pointcut.PointcutService;
import io.security.corespringsecurity.domain.dto.AccountDTO;
import org.springframework.aop.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;

@Controller
public class AopSecurityController {

    @Autowired
    private Source source;

    @Autowired
    private AopMethodService aopMethodService;

    @Autowired
    private PointcutService pointcutService;

    @Autowired
    private AopLiveMethodService aopLiveMethodService;


    @GetMapping("/preAuthorize")
    @PreAuthorize("hasRole('ROLE_USER') and #accountDTO.username == principal.username")
    public String preAuthorize(AccountDTO accountDTO, Model model, Principal principal) {
        model.addAttribute("method", "Success @PreAuthorize");

        return "aop/method";
    }

    @GetMapping("/authorization")
    @ResponseBody
    public String authorization() {
        return "authorization";
    }



    @GetMapping("/source")
    @ResponseBody
    public String source() {
        // 직접 생성하여서는 안된다.
        // Source source = new Source();
        return source.getSource();
    }



    @GetMapping("methodSecured")
    public String methodSecured(Model model) {
        aopMethodService.methodSecured();
        model.addAttribute("method", "Success MethodSecured");

        return "aop/method";
    }



    @GetMapping("pointcutSecured")
    public String pointcutSecured(Model model) {
        pointcutService.pointcutSecured();
        model.addAttribute("method", "Success pointcutSecured");

        return "aop/method";
    }

    @GetMapping("aopLiveMethodSecured")
    public String aopLiveMethodSecured(Model model) {
        aopLiveMethodService.aopLiveMethodSecured();
        model.addAttribute("method", "Success aopLiveMethodSecured");

        return "aop/method";
    }

}
