package com.furkan.userregistration.repository;

import com.furkan.userregistration.model.Account;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccountRepository extends MongoRepository<Account, String> {

    boolean existsByUsername(String username);

    Optional<Account> findByUsername(String username);
}

