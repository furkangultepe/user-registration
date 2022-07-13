package com.furkan.userregistration.service;

import com.furkan.userregistration.model.Account;
import com.furkan.userregistration.payload.SignUpRequest;
import com.furkan.userregistration.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AccountService {
    private final PasswordEncoder passwordEncoder;
    private final AccountRepository accountRepository;

    public Account create(SignUpRequest request) {
        if (accountRepository.existsByUsername(request.getUsername()))
            throw new BadCredentialsException("Username already exists");
        return accountRepository.insert(
                Account.builder()
                       .creationDate(System.currentTimeMillis())
                       .username(request.getUsername())
                       .password(passwordEncoder.encode(request.getPassword()))
                       .roles(List.of("ROLE_USER", "ROLE_ADMIN"))
                       .disabled(false)
                       .build()
        );

    }

    public List<Account> getAll() {
        return accountRepository.findAll();
    }

    public void deleteById(String id) {
        accountRepository.deleteById(id);

    }

    public Account updateAccount(Account account) {
        account.setPassword((passwordEncoder.encode(account.getPassword())));
        return accountRepository.save(account);
    }

    public Account saveRole(Account account) {
        return accountRepository.save(saveRole(account));
    }

}
