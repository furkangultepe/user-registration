package com.furkan.userregistration.payload;

import lombok.Data;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;


import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.util.function.Supplier;

@Data
public class SignInRequest implements Supplier<UsernamePasswordAuthenticationToken> {
    @NotNull
    @NotBlank
    private String username;

    @NotNull
    @NotBlank
    private String password;


    @Override
    public UsernamePasswordAuthenticationToken get() {
        return new UsernamePasswordAuthenticationToken(username, password);
    }
}
