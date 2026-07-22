package com.acme;

public class JavaCaller {
    public void invokeKotlin(KotlinService service) {
        service.kotlinCall(this);
    }

    public void javaCall() {
    }
}
