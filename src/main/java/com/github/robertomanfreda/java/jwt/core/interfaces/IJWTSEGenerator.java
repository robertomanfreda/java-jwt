package com.github.robertomanfreda.java.jwt.core.interfaces;

import java.util.Map;

public interface IJWTSEGenerator {

    String generate(String issuer, String audience, Map<String, Object> claims, long ttlSeconds) throws Exception;

}
