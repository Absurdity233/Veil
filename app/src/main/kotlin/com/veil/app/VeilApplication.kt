package com.veil.app

import android.app.Application

/**
 * Process-wide wiring.
 *
 * The chat controller is a singleton because the relay connection and the
 * native engine both have process lifetime. Keeping it out of the ViewModel
 * means a configuration change does not tear down the socket.
 */
class VeilApplication : Application() {

    lateinit var controller: ChatController
        private set

    override fun onCreate() {
        super.onCreate()
        controller = ChatController(this)
    }
}
