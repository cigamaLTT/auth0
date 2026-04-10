package com.cigama.auth0.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "client_apps")
public class ClientApp extends BaseAuditEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID clientId;

    @Column(name = "name", nullable = false, unique = true)
    private String clientName;

    /// this token is used for third party member use our api for their auth
    @Column(name = "api_token", nullable = false, updatable = false, unique = true)
    private String clientToken;

    @Column(name = "redirect_url", nullable = false, updatable = false)
    private String redirectUrl;
}