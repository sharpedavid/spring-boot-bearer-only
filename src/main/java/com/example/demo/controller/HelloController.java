package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@RestController
public class HelloController {

    @Autowired
    RestTemplate restTemplate;

    @Autowired
    private WebClient webClient;

    @GetMapping("/")
    public String index() {
        return "<html><body>Greetings from Spring Boot!<br/>" +
                "<a href=\"rest-template\">rest-template</a><br/>" +
                "<a href=\"webclient\">webclient</a><br/>" +
                "<a href=\"webclient-notoken\">webclient-notoken</a><br/>" +
                "<a href=\"admin\">admin</a><br/>" +
                "</body><html>";
    }

    @GetMapping(value = "/rest-template", produces = { "application/json"})
    public String service() {
        return restTemplate.getForObject("https://common-logon-dev.hlth.gov.bc.ca/auth/admin/realms/moh_applications/users/6851d194-0167-4281-be3d-3a35795c820a", String.class);
    }

    @GetMapping(value = "/webclient", produces = { "application/json"})
    public String service1(@RegisteredOAuth2AuthorizedClient("messaging-client-client-creds") OAuth2AuthorizedClient authorizedClient) {
        String block = webClient.get()
                .uri("https://common-logon-dev.hlth.gov.bc.ca/auth/admin/realms/moh_applications/users/6851d194-0167-4281-be3d-3a35795c820a")
                .attributes(oauth2AuthorizedClient(authorizedClient)).retrieve().bodyToMono(String.class).block();
        return block;
    }

    @GetMapping(value = "/webclient-notoken", produces = { "application/json"})
    public String get() {
        WebClient webClient = WebClient.create("https://httpbin.org/get");
        String block = webClient.get().retrieve().bodyToMono(String.class).block();
        return block;
    }

    @GetMapping("/admin")
    public String admin() {
        return "Secured page";
    }

}