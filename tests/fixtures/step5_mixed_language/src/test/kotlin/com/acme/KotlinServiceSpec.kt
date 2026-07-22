package com.acme

class KotlinServiceSpec {
    fun verifiesProductionService(service: KotlinService) {
        service.kotlinCall(JavaCaller())
    }
}
