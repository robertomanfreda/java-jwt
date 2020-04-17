package com.github.robertomanfreda.java.jwt;

import java.util.Map;

interface IJWTSEGenerator {

    String generate(String issuer, String audience, Map<String, Object> claims, long ttlSeconds) throws Exception;

}
