package com.cigama.auth0.entity;

import jakarta.persistence.*;

import java.util.UUID;

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

    public ClientApp() {}

    public UUID getClientId() {
        return clientId;
    }

    public void setClientId(UUID clientId) {
        this.clientId = clientId;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public String getClientToken() {
        return clientToken;
    }

    public void setClientToken(String clientToken) {
        this.clientToken = clientToken;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }
}
