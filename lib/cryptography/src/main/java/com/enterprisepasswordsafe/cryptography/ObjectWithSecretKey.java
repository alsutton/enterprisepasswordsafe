package com.enterprisepasswordsafe.cryptography;

import javax.crypto.SecretKey;

public interface ObjectWithSecretKey {

    SecretKey getKey();
}
