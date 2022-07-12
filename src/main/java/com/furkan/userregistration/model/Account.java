package com.furkan.userregistration.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection="account")
public class Account {
    private String id;
    private String name;
    private long creationDate;
    private long updatedDate;
    private String username;
    private String password;
    private String phone;
    private double salary;
    private String title;
    private int foodCardNumber;
    private List<String> roles;
    private boolean disabled;

}
