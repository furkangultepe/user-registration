package com.furkan.userregistration.controller;


import com.furkan.userregistration.configuration.JwtTokenProvider;
import com.furkan.userregistration.model.Account;
import com.furkan.userregistration.payload.SignInRequest;
import com.furkan.userregistration.payload.SignUpRequest;
import com.furkan.userregistration.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class AccountController {
    private final AccountService accountService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/accounts")
    public ResponseEntity<List<Account>> getUsers(){
        return ResponseEntity.ok().body(accountService.getAll());
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PostMapping("/account/save")
    public ResponseEntity<Account> updateAccount(@RequestBody Account account){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/account/update").toUriString());
        return ResponseEntity.created(uri).body(accountService.updateAccount(account));
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @DeleteMapping("/account/delete")
    public void deleteById(String id) {
        accountService.deleteById(id);
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PostMapping("/role/save")
    public ResponseEntity<Account> saveRole(@RequestBody Account account){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/role/save").toUriString());
        return ResponseEntity.created(uri).body(accountService.saveRole(account));
    }

    @PostMapping("/sign-in")
    public ResponseEntity<?> signIn(@Valid @RequestBody SignInRequest request)
    throws SecurityException {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(request.get());
        } catch (DisabledException e) {
            throw new SecurityException("Account disabled");
        } catch (BadCredentialsException e) {
            throw new SecurityException("Wrong account credentials");
        }

        String jwt = jwtTokenProvider.createToken(authentication.getName(), authentication.getAuthorities());
        Map<String, Object> responseBody = Map.of(
                "idToken", jwt,
                "tokenType", "Bearer",
                "roles", authentication.getAuthorities()
        );

        return ResponseEntity.ok()
                             .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                             .body(responseBody);
    }

    @PostMapping("/sign-up")
    public ResponseEntity<?> signUp(@Valid @RequestBody SignUpRequest request) {
        Account account = accountService.create(request);
        account.setPassword("?secret?");
        return ResponseEntity.ok(account);
    }
}
