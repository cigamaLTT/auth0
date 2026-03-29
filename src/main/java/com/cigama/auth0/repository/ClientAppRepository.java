package com.cigama.auth0.repository;

import com.cigama.auth0.entity.ClientApp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface ClientAppRepository extends JpaRepository<ClientApp, UUID> {

    Optional<ClientApp> findByClientName(String clientName);

    boolean existsByClientName(String clientName);

    Optional<ClientApp> findByClientToken(String clientToken);

}
