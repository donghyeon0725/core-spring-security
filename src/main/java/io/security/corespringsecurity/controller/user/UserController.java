package io.security.corespringsecurity.controller.user;


import io.security.corespringsecurity.common.ModelMapperUtil;
import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.domain.dto.AccountDTO;
import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {

	private final UserService userService;

	private final PasswordEncoder passwordEncoder;

	@GetMapping(value="/mypage")
	public String myPage() throws Exception {
		return "user/mypage";
	}

	@GetMapping("/users")
	public String createUser() {
		return "user/login/register";
	}

	@PostMapping("/users")
	public String createUser(AccountDTO accountDTO) {
		Account account = ModelMapperUtil.copyMember(accountDTO, Account.class);
		account.setPassword(passwordEncoder.encode(account.getPassword()));
		userService.createUser(account);

		return "redirect:/";
	}
}
